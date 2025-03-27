//go:build !nogvisor && linux && (amd64 || arm64)

package tun

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/phuslu/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/xdp"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/yaling888/quirktiva/adapter/inbound"
	"github.com/yaling888/quirktiva/common/hostos"
	"github.com/yaling888/quirktiva/common/uuid"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/commons"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/gvisor"
)

type xdpAdapter struct {
	device   string
	stack    *stack.Stack
	endpoint stack.LinkEndpoint
	cleanup1 func()
	cleanup2 func()
	cleanup3 func()
}

func (x *xdpAdapter) Close() error {
	if x == nil {
		return nil
	}
	if x.stack != nil {
		x.stack.Close()
	}
	if x.endpoint != nil {
		x.endpoint.Close()
	}
	if x.cleanup1 != nil {
		x.cleanup1()
	}
	if x.cleanup2 != nil {
		x.cleanup2()
	}
	if x.cleanup3 != nil {
		x.cleanup3()
	}
	if x.device != "" {
		if ln, err := netlink.LinkByName(x.device); err == nil {
			_ = netlink.LinkSetDown(ln)
			_ = netlink.LinkDel(ln)
		}
	}
	return nil
}

func newXDPAdapter(tunConf *C.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (adp *xdpAdapter, err error) {
	version := hostos.KernelVersion()
	if version.LessThan(5, 5) {
		return nil, fmt.Errorf("XDP stack requires Linux kernel >= %s", version)
	}

	defer func() {
		if err != nil {
			if adp != nil {
				_ = adp.Close()
			}
		}
	}()

	hostName := tunConf.Device
	vethName := "veth_" + uuid.RandomB58Hlf().String58Hlf()[:5]

	if u, err := url.Parse(tunConf.Device); err == nil {
		hostName = u.Host
	}

	vethMACAddr := randLinkAddress()

	veth := netlink.Veth{ // Turn off GSO, GRO, and LRO. Limit veth MTU to 1500.
		LinkAttrs: netlink.LinkAttrs{
			Name:           hostName,
			MTU:            1500, // 1500 is sized to ensure packets fit inside a 2048 byte AF_XDP frame.
			TxQLen:         1000,
			NumRxQueues:    1, // use one queue for now
			NumTxQueues:    1,
			GSOMaxSize:     0,
			GSOMaxSegs:     0,
			GSOIPv4MaxSize: 0,
			GROMaxSize:     0,
			GROIPv4MaxSize: 0,
			HardwareAddr:   randLinkAddress(),
		},
		PeerName:         vethName,
		PeerHardwareAddr: vethMACAddr,
	}

again:
	if err = netlink.LinkAdd(&veth); err != nil {
		if os.IsExist(err) {
			if ln, er := netlink.LinkByName(hostName); er == nil {
				if ln.Type() == "veth" || ln.Type() == "tuntap" {
					if netlink.LinkDel(ln) == nil {
						goto again
					}
				}
			}
		}
		return nil, fmt.Errorf("failed to create veth pair devices: %w", err)
	}

	adp = &xdpAdapter{device: hostName}

	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return adp, fmt.Errorf("failed to get interface, name: %s, error: %w", hostName, err)
	}

	var fakeIP4, fakeIP6 netip.Prefix
	if tunConf.TunAddressPrefix != nil {
		fakeIP4 = *tunConf.TunAddressPrefix
	}
	if tunConf.TunAddressPrefix6 != nil {
		fakeIP6 = *tunConf.TunAddressPrefix6
	}

	if err = commons.ConfigInterfaceAddressAndRoutes(hostLink, fakeIP4, fakeIP6, tunConf.AutoRoute, true); err != nil {
		return adp, err
	}

	vethLink, err := netlink.LinkByName(vethName)
	if err != nil {
		return adp, fmt.Errorf("failed to get interface, name: %s, error: %w", vethName, err)
	}

	if err = commons.ConfigInterfaceAddressAndRoutes(vethLink, fakeIP4, fakeIP6, false, false); err != nil {
		return adp, err
	}

	vethIndex := vethLink.Attrs().Index

	xskSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(afXDPProgram))
	if err != nil {
		return adp, fmt.Errorf("failed to load xks spec: %w", err)
	}

	var xskObjs struct {
		XskRedirProg *ebpf.Program `ebpf:"xsk_redir_prog"`
		XsksMap      *ebpf.Map     `ebpf:"xsks_map"`
	}
	if err = xskSpec.LoadAndAssign(&xskObjs, nil); err != nil {
		return adp, fmt.Errorf("failed to load xks program: %w", err)
	}

	adp.cleanup3 = func() {
		_ = xskObjs.XskRedirProg.Close()
		_ = xskObjs.XsksMap.Close()
	}

	xdpSockFD, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return adp, fmt.Errorf("failed to create AF_XDP socket: %w", err)
	}

	adp.cleanup2 = func() {
		_ = unix.Close(xdpSockFD)
	}

	mapKey := uint32(0)
	xskMapValue := uint32(xdpSockFD)
	if err = xskObjs.XsksMap.Update(&mapKey, &xskMapValue, ebpf.UpdateAny); err != nil {
		return adp, fmt.Errorf("failed to insert socket into xks map: %w", err)
	}

	linkAddress := tcpip.LinkAddress(vethMACAddr)
	xdpEP, err := xdp.New(&xdp.Options{
		FD:                xdpSockFD,
		Address:           linkAddress,
		InterfaceIndex:    vethIndex,
		TXChecksumOffload: false,
		RXChecksumOffload: true,
		Bind:              true,
		GRO:               false,
	})
	if err != nil {
		return adp, fmt.Errorf("failed to create XDP endpoint: %w", err)
	}

	adp.endpoint = xdpEP

	s, err := gvisor.NewStack(tunConf.DNSHijack, fakeIP4, fakeIP6, tcpIn, udpIn, C.XDP)
	if err != nil {
		return adp, fmt.Errorf("failed to create XDP stack: %w", err)
	}

	adp.stack = s

	nicID := s.NextNICID()
	nicOpts := stack.NICOptions{
		Name: vethName,
		// QDisc:              fifo.New(xdpEP, runtime.GOMAXPROCS(-1), 1000),
		// DeliverLinkPackets: true,
	}

	// for debug
	// xdpEP = sniffer.New(xdpEP)

	if err = gvisor.CreateNICWithOptions(s, xdpEP, nicID, nicOpts); err != nil {
		return adp, fmt.Errorf("failed to create XDP NIC: %w", err)
	}

	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Name == "lo" {
				continue
			}
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ip, ok := addr.(*net.IPNet); ok {
						proto, tcpipAddr := ipToAddressAndProto(ip.IP)
						s.AddStaticNeighbor(nicID, proto, tcpipAddr, tcpip.LinkAddress(iface.HardwareAddr))
					}
				}
			}
		}
	}

	var attachedMode string
	_, attachedMode, adp.cleanup1, err = attach(xskObjs.XskRedirProg, vethIndex)
	if err != nil {
		return adp, err
	}

	setAtLatest(0, hostName, vethName)

	log.Info().
		Str("iface", hostName).
		NetIPAddr("gateway4", commons.GetFirstAvailableIP(fakeIP4).Next()).
		NetIPAddr("gateway6", commons.GetFirstAvailableIP(fakeIP6).Next()).
		Int("mtu", 1500).
		Bool("autoRoute", tunConf.AutoRoute).
		Str("ipStack", "XDP").
		Str("mode", attachedMode).
		Msg("[Inbound] tun listening")

	return adp, nil
}

func attach(program *ebpf.Program, ifindx int) (link.Link, string, func(), error) {
	modes := []struct {
		name string
		flag link.XDPAttachFlags
	}{
		{name: "offload", flag: link.XDPOffloadMode},
		{name: "driver", flag: link.XDPDriverMode},
		{name: "generic", flag: link.XDPGenericMode},
	}
	var currentMode string
	var attached link.Link
	var err error
	for _, mode := range modes {
		attached, err = link.AttachXDP(link.XDPOptions{
			Program:   program,
			Interface: ifindx,
			Flags:     mode.flag,
		})
		if err == nil {
			currentMode = mode.name
			break
		}
	}
	if attached == nil {
		return nil, "", nil, fmt.Errorf("failed to attach program: %w", err)
	}
	return attached, currentMode, func() { _ = attached.Close() }, nil
}

//go:embed ipstack/xdp/af_xdp_sock_bpf.o
var afXDPProgram []byte
