//go:build !nogvisor && linux

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"unsafe"

	"github.com/phuslu/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/yaling888/quirktiva/adapter/inbound"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/commons"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/gvisor"
)

type fdAdapter struct {
	device   string
	stack    *stack.Stack
	endpoint stack.LinkEndpoint
}

func (x *fdAdapter) Close() error {
	if x == nil {
		return nil
	}
	if x.stack != nil {
		x.stack.Close()
	}
	if x.endpoint != nil {
		x.endpoint.Close()
	}
	if x.device != "" {
		if ln, err := netlink.LinkByName(x.device); err == nil {
			_ = netlink.LinkSetDown(ln)
			_ = netlink.LinkDel(ln)
		}
	}
	return nil
}

func newFDAdapter(tunConf *C.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter, isTAP bool) (adp *fdAdapter, err error) {
	defer func() {
		if err != nil {
			if adp != nil {
				_ = adp.Close()
			}
		}
	}()

	deviceName := tunConf.Device
	if u, err := url.Parse(tunConf.Device); err == nil {
		deviceName = u.Host
	}

	var prefix4, prefix6 netip.Prefix
	if tunConf.TunAddressPrefix != nil {
		prefix4 = *tunConf.TunAddressPrefix
	}
	if tunConf.TunAddressPrefix6 != nil {
		prefix6 = *tunConf.TunAddressPrefix6
	}

	mtu := 64<<10 - 1
	gso := false
	tp := C.TUN
	if isTAP {
		mtu -= 24
		gso = true
		tp = C.TAP
	}

	fds, mac, gsoMaxSize, err := getFDs(deviceName, mtu, prefix4, prefix6, tunConf.AutoRoute, isTAP, false, gso)
	if err != nil {
		return
	}

	adp = &fdAdapter{device: deviceName}

	dispatchMode := fdbased.RecvMMsg
	//version := hostos.KernelVersion()
	//if version.AtLeast(5, 6) {
	//	// TODO: Switch back to using the packet mmap dispatcher when
	//	// we have the performance data to justify it.
	//	// dispatchMode = fdbased.PacketMMap
	//	// log.Info().Msg("[gVisor] host kernel version >= 5.6, using to packet mmap to dispatch")
	//} else {
	//	log.Info().Msg("[gVisor] host kernel version < 5.6, using to RecvMMsg to dispatch")
	//}

	linkAddress := tcpip.LinkAddress(mac)

	gVisorGSOEnabled := false
	if gsoMaxSize == 0 && gso {
		// Host GSO is disabled. Let's enable gVisor GSO.
		gsoMaxSize = stack.GVisorGSOMaxSize
		gVisorGSOEnabled = true
	}

	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:                  fds,
		MTU:                  uint32(mtu),
		EthernetHeader:       isTAP,
		Address:              linkAddress,
		PacketDispatchMode:   dispatchMode,
		GSOMaxSize:           gsoMaxSize,
		GVisorGSOEnabled:     gVisorGSOEnabled,
		TXChecksumOffload:    false,
		RXChecksumOffload:    true,
		GRO:                  isTAP,
		ProcessorsPerChannel: 0,
	})
	if err != nil {
		return adp, fmt.Errorf("failed to create fdbased endpoint: %w", err)
	}

	adp.endpoint = linkEP

	s, err := gvisor.NewStack(tunConf.DNSHijack, prefix4, prefix6, tcpIn, udpIn, tp)
	if err != nil {
		return adp, fmt.Errorf("failed to create gVisor stack: %w", err)
	}

	adp.stack = s

	nicID := s.NextNICID()
	nicOpts := stack.NICOptions{
		Name: deviceName,
		// QDisc:              fifo.New(linkEP, runtime.GOMAXPROCS(-1), 1000),
		// DeliverLinkPackets: isTAP,
	}

	// for debug
	// linkEP = sniffer.New(linkEP)

	if err = gvisor.CreateNICWithOptions(s, linkEP, nicID, nicOpts); err != nil {
		return adp, fmt.Errorf("failed to create gVisor NIC: %w", err)
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

	log.Info().
		Str("iface", deviceName).
		NetIPAddr("gateway4", commons.GetFirstAvailableIP(prefix4)).
		NetIPAddr("gateway6", commons.GetFirstAvailableIP(prefix6)).
		Int("mtu", mtu).
		Uint32("gsoMaxSize", gsoMaxSize).
		Bool("autoRoute", tunConf.AutoRoute).
		Str("ipStack", "gVisor").
		Str("mode", tp.String()).
		Msg("[Inbound] tun listening")

	return adp, nil
}

func getFDs(name string, mtu int, prefix4, prefix6 netip.Prefix, autoRoute, tap, socket, gso bool) (fds []int, mac []byte, gsoMaxSize uint32, err error) {
	if tap {
		fd, er := tun.OpenTAP(name)
		if er != nil {
			err = fmt.Errorf("failed to create tap device: %w", er)
			return
		}
		if !socket {
			fds = []int{fd}
		}
	} else {
		fd, er := tun.Open(name)
		if er != nil {
			err = fmt.Errorf("failed to create tun device: %w", er)
			return
		}
		fds = []int{fd}
	}

	defer func() {
		if err != nil {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
		}
	}()

	link, err := netlink.LinkByName(name)
	if err != nil {
		err = fmt.Errorf("failed to get tuntap device: %w", err)
		return
	}
	defer func() {
		if err != nil {
			_ = netlink.LinkDel(link)
		}
	}()

	if err = netlink.LinkSetUp(link); err != nil {
		err = fmt.Errorf("failed to set tuntap device up: %w", err)
		return
	}

	if err = netlink.LinkSetMTU(link, mtu); err != nil {
		err = fmt.Errorf("failed to set tuntap mtu: %w", err)
		return
	}

	if err = commons.ConfigInterfaceAddressAndRoutes(link, prefix4, prefix6, autoRoute, false); err != nil {
		return
	}

	if tap {
		mac = randLinkAddress()
		if err = netlink.LinkSetHardwareAddr(link, mac); err != nil {
			err = fmt.Errorf("failed to set tap device hardware address: %w", err)
			return
		}

		if socket {
			// create the socket for the device.
			for i := 0; i < runtime.GOMAXPROCS(-1); i++ {
				entry, er := createSocket(link, gso)
				if er != nil {
					err = fmt.Errorf("failed to create socket for %s : %w", name, er)
					return
				}
				if i == 0 {
					gsoMaxSize = entry.gsoMaxSize
				} else {
					if gsoMaxSize != entry.gsoMaxSize {
						err = fmt.Errorf("inconsistent gsoMaxSize %d and %d when creating multiple channels for same interface: %s",
							gsoMaxSize, entry.gsoMaxSize, name)
						return
					}
				}
				fds = append(fds, entry.socketFD)
			}
		}
	}

	setAtLatest(0, name)
	return
}

type socketEntry struct {
	socketFD   int
	gsoMaxSize uint32
}

// createSocket creates an underlying AF_PACKET socket
func createSocket(link netlink.Link, enableGSO bool) (*socketEntry, error) {
	// Create the socket.
	const protocol = 0x0300                                  // htons(ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0) // pass protocol 0 to avoid slow bind()
	if err != nil {
		return nil, fmt.Errorf("unable to create raw socket: %w", err)
	}
	// Bind to the appropriate device.
	ll := unix.SockaddrLinklayer{
		Protocol: protocol,
		Ifindex:  link.Attrs().Index,
	}
	if err := unix.Bind(fd, &ll); err != nil {
		return nil, fmt.Errorf("unable to bind to %q: %w", link.Attrs().Name, err)
	}

	gsoMaxSize := uint32(0)
	if enableGSO {
		gso, err := isGSOEnabled(fd, link.Attrs().Name)
		if err != nil {
			return nil, fmt.Errorf("getting GSO for interface %q: %w", link.Attrs().Name, err)
		}
		if gso {
			if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VNET_HDR, 1); err != nil {
				return nil, fmt.Errorf("unable to enable the PACKET_VNET_HDR option: %w", err)
			}
			gsoMaxSize = link.Attrs().GSOMaxSize
		} else {
			log.Info().Msg("[gVisor] GSO not available in host.")
		}
	}

	// Use SO_RCVBUFFORCE/SO_SNDBUFFORCE because on linux the receive/send buffer
	// for an AF_PACKET socket is capped by "net.core.rmem_max/wmem_max".
	// wmem_max/rmem_max default to a unusually low value of 208KB. This is too
	// low for gVisor to be able to receive packets at high throughputs without
	// incurring packet drops.
	const bufSize = 4 << 20 // 4MB.

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, bufSize); err != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufSize)
		sz, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)

		if sz < bufSize {
			log.Warn().Msgf("[gVisor] failed to increase rcv buffer to %d on SOCK_RAW on %s. Current buffer %d: %s", bufSize, link.Attrs().Name, sz, err)
		}
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, bufSize); err != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, bufSize)
		sz, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
		if sz < bufSize {
			log.Warn().Msgf("[gVisor] failed to increase snd buffer to %d on SOCK_RAW on %s. Current buffer %d: %s", bufSize, link.Attrs().Name, sz, err)
		}
	}

	return &socketEntry{fd, gsoMaxSize}, nil
}

type ethtoolValue struct {
	cmd uint32
	val uint32
}

type ifreq struct {
	ifrName [unix.IFNAMSIZ]byte
	ifrData *ethtoolValue
}

func isGSOEnabled(fd int, intf string) (bool, error) {
	val := ethtoolValue{
		cmd: unix.ETHTOOL_GGSO,
	}

	var name [unix.IFNAMSIZ]byte
	copy(name[:], intf)

	ifr := ifreq{
		ifrName: name,
		ifrData: &val,
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&ifr))); err != 0 {
		return false, err
	}

	return val.val != 0, nil
}
