//go:build linux

package redir

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -no-global-types -tags linux bpf ../bpf/redir.c

type EBpfRedirect struct {
	tcpMap *ebpf.Map
	udpMap *ebpf.Map

	linkIngress link.Link
	linkEgress  link.Link

	qdisc         netlink.Qdisc
	filterIngress netlink.Filter
	filterEgress  netlink.Filter

	ifName        string
	ifIndex       int
	redirAddrPort netip.AddrPort
	redirAddr6    netip.Addr

	fakeIP4Prefix uint32 // host byte order
	fakeIP6Prefix [8]byte
}

func NewEBpfRedirect(ifName string, ifIndex int, redirAddrPort netip.AddrPort, redirAddr6 netip.Addr, fakeIP4Prefix, fakeIP6Prefix *netip.Prefix) *EBpfRedirect {
	redir := &EBpfRedirect{
		ifName:        ifName,
		ifIndex:       ifIndex,
		redirAddrPort: redirAddrPort,
		redirAddr6:    redirAddr6,
	}

	if fakeIP4Prefix != nil {
		a4 := netip.PrefixFrom(fakeIP4Prefix.Addr(), 16).Masked().Addr().As4()
		redir.fakeIP4Prefix = binary.BigEndian.Uint32(a4[:])
	}

	if fakeIP6Prefix != nil {
		a16 := netip.PrefixFrom(fakeIP6Prefix.Addr(), 64).Masked().Addr().As16()
		redir.fakeIP6Prefix = [8]byte(a16[:8])
	}

	return redir
}

func (e *EBpfRedirect) Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memory lock: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading collection spec: %w", err)
	}

	tmp := e.redirAddrPort.Addr().As16()
	if err = spec.Variables["redir_ip4"].Set(tmp[:]); err != nil {
		return fmt.Errorf("setting variable redir_ip4 value: %w", err)
	}

	tmp = e.redirAddr6.As16()
	if err = spec.Variables["redir_ip6"].Set(tmp[:]); err != nil {
		return fmt.Errorf("setting variable redir_ip6 value: %w", err)
	}

	binary.BigEndian.PutUint16(tmp[:], e.redirAddrPort.Port())
	if err = spec.Variables["redir_port"].Set(tmp[:2]); err != nil {
		return fmt.Errorf("setting variable redir_port value: %w", err)
	}

	if err = spec.Variables["fake_ip4_prefix"].Set(e.fakeIP4Prefix); err != nil {
		return fmt.Errorf("setting variable fake_ip4_prefix value: %w", err)
	}

	if err = spec.Variables["fake_ip6_prefix"].Set(e.fakeIP6Prefix[:]); err != nil {
		return fmt.Errorf("setting variable fake_ip6_prefix value: %w", err)
	}

	var objs bpfObjects
	if err = spec.LoadAndAssign(&objs, nil); err != nil {
		e.Close()
		return fmt.Errorf("loading objects: %w", err)
	}

	defer func() {
		_ = objs.bpfPrograms.Close()
	}()

	e.tcpMap = objs.TcpMap
	e.udpMap = objs.UdpMap

	if e.linkIngress, e.linkEgress, err = attachTCx(e.ifIndex, objs.TcRedirIngressFunc, objs.TcRedirEgressFunc); err == nil {
		return nil
	}

	e.detach()

	// fallback attach generic
	e.qdisc, e.filterIngress, e.filterEgress, err = attachGenericTC(e.ifIndex, objs.TcRedirIngressFunc.FD(), objs.TcRedirEgressFunc.FD())
	if err != nil {
		e.Close()
		return err
	}

	return nil
}

// attachTCx for the kernel version >= 6.6
func attachTCx(ifIndex int, ingress, egress *ebpf.Program) (linkIngress, linkEgress link.Link, err error) {
	linkIngress, err = link.AttachTCX(link.TCXOptions{
		Interface: ifIndex,
		Program:   ingress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		err = fmt.Errorf("could not attach TCx ingress program: %w", err)
		return
	}

	linkEgress, err = link.AttachTCX(link.TCXOptions{
		Interface: ifIndex,
		Program:   egress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		err = fmt.Errorf("could not attach TCx egress program: %w", err)
	}

	return
}

func attachGenericTC(ifIndex, ingressFD, egressFD int) (qdisc netlink.Qdisc, filterIngress, filterEgress netlink.Filter, err error) {
	qdisc = &netlink.GenericQdisc{
		QdiscType: "clsact",
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	if err = netlink.QdiscAdd(qdisc); err != nil {
		if os.IsExist(err) {
			_ = netlink.QdiscDel(qdisc)
			err = netlink.QdiscAdd(qdisc)
		}
		if err != nil {
			err = fmt.Errorf("failed to add clsact qdisc: %w", err)
			return
		}
	}

	filterIngress = &netlink.BpfFilter{
		Fd:           ingressFD,
		Name:         fmt.Sprintf("clash-redir-ingress-%d", ifIndex),
		DirectAction: true,
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
	}
	if err = netlink.FilterAdd(filterIngress); err != nil {
		err = fmt.Errorf("could not attach tc ingress program: %w", err)
		return
	}

	filterEgress = &netlink.BpfFilter{
		Fd:           egressFD,
		Name:         fmt.Sprintf("clash-redir-egress-%d", ifIndex),
		DirectAction: true,
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  0,
		},
	}
	if err = netlink.FilterAdd(filterEgress); err != nil {
		err = fmt.Errorf("could not attach tc egress program: %w", err)
	}

	return
}

func (e *EBpfRedirect) Close() {
	e.detach()
}

func (e *EBpfRedirect) detach() {
	if e.linkIngress != nil {
		_ = e.linkIngress.Close()
		e.linkIngress = nil
	}
	if e.linkEgress != nil {
		_ = e.linkEgress.Close()
		e.linkEgress = nil
	}
	if e.filterIngress != nil {
		_ = netlink.FilterDel(e.filterIngress)
		e.filterIngress = nil
	}
	if e.filterEgress != nil {
		_ = netlink.FilterDel(e.filterEgress)
		e.filterEgress = nil
	}
	if e.qdisc != nil {
		_ = netlink.QdiscDel(e.qdisc)
		e.qdisc = nil
	}
}

func (e *EBpfRedirect) Lookup(srcAddrPort netip.AddrPort) (netip.AddrPort, error) {
	key := tuple{AddrPort: srcAddrPort}
	value := tuple{}

	if err := e.tcpMap.Lookup(key, &value); err != nil {
		return netip.AddrPort{}, err
	}

	return value.AddrPort, nil
}

func (e *EBpfRedirect) LookupUDP(srcAddrPort netip.AddrPort) (netip.AddrPort, error) {
	key := tuple{AddrPort: srcAddrPort}
	value := tuple{}

	if err := e.udpMap.Lookup(key, &value); err != nil {
		return netip.AddrPort{}, err
	}

	return value.AddrPort, nil
}

type tuple struct {
	AddrPort netip.AddrPort
}

func (t tuple) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 0, 20)
	a16 := t.AddrPort.Addr().As16()
	data = append(data, a16[:]...)
	binary.BigEndian.PutUint16(data[16:18], t.AddrPort.Port())
	data = data[:20]
	return
}

func (t *tuple) UnmarshalBinary(data []byte) error {
	if l := len(data); l < 18 {
		return fmt.Errorf("invalid data length: %d", l)
	}
	t.AddrPort = netip.AddrPortFrom(netip.AddrFrom16([16]byte(data[:16])), binary.BigEndian.Uint16(data[16:]))
	return nil
}
