//go:build linux

package tc

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/yaling888/quirktiva/common/hostos"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -tags linux bpf ../bpf/tc.c

type EBpfTC struct {
	link   link.Link
	qdisc  netlink.Qdisc
	filter netlink.Filter

	ifName     string
	ifIndex    int
	ifMark     uint32
	tunIfIndex uint32
	tunMAC     [6]byte

	fakeIP4Prefix uint32 // host byte order
	fakeIP6Prefix [8]byte
}

func NewEBpfTc(ifName string, ifIndex int, ifMark uint32, tunIfIndex uint32, tunMAC []byte, fakeIP4Prefix, fakeIP6Prefix *netip.Prefix) *EBpfTC {
	tc := &EBpfTC{
		ifName:     ifName,
		ifIndex:    ifIndex,
		ifMark:     ifMark,
		tunIfIndex: tunIfIndex,
	}

	if len(tunMAC) == 6 {
		tc.tunMAC = [6]byte(tunMAC)
	}

	if fakeIP4Prefix != nil {
		a4 := netip.PrefixFrom(fakeIP4Prefix.Addr(), 16).Masked().Addr().As4()
		tc.fakeIP4Prefix = binary.BigEndian.Uint32(a4[:])
	}

	if fakeIP6Prefix != nil {
		a16 := netip.PrefixFrom(fakeIP6Prefix.Addr(), 64).Masked().Addr().As16()
		tc.fakeIP6Prefix = [8]byte(a16[:8])
	}

	return tc
}

func (e *EBpfTC) Start() error {
	version := hostos.KernelVersion()
	if version.LessThan(5, 11) { // remove resource limits for kernels < v5.11.
		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("remove memory lock: %w", err)
		}
	}

	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading collection spec: %w", err)
	}

	var prog *ebpf.Program

	if version.AtLeast(5, 5) { // the Variable API requires kernel >= v5.5
		if err = spec.Variables["clash_mark"].Set(e.ifMark); err != nil {
			return fmt.Errorf("setting variable clash_mark value: %w", err)
		}

		if err = spec.Variables["tun_ifindex"].Set(e.tunIfIndex); err != nil {
			return fmt.Errorf("setting variable tun_ifindex value: %w", err)
		}

		if err = spec.Variables["fake_ip4_prefix"].Set(e.fakeIP4Prefix); err != nil {
			return fmt.Errorf("setting variable fake_ip4_prefix value: %w", err)
		}

		if err = spec.Variables["fake_ip6_prefix"].Set(e.fakeIP6Prefix[:]); err != nil {
			return fmt.Errorf("setting variable fake_ip6_prefix value: %w", err)
		}

		if err = spec.Variables["tun_mac"].Set(e.tunMAC[:]); err != nil {
			return fmt.Errorf("setting variable tun_mac value: %w", err)
		}

		var objs struct {
			TcTun55Func *ebpf.Program `ebpf:"tc_tun_5_5_func"`
			bpfVariables
		}

		delete(spec.Maps, "params_map")
		if err = spec.LoadAndAssign(&objs, nil); err != nil {
			e.Close()
			return fmt.Errorf("loading objects: %w", err)
		}

		prog = objs.TcTun55Func

		defer func() {
			_ = prog.Close()
		}()
	} else {
		var objs struct {
			TcTunFunc *ebpf.Program `ebpf:"tc_tun_func"`
			bpfMaps
		}

		clear(spec.Variables)
		delete(spec.Maps, ".rodata")

		if err = spec.LoadAndAssign(&objs, nil); err != nil {
			e.Close()
			return fmt.Errorf("loading objects: %w", err)
		}

		params := bpfParams{
			ClashMark:     e.ifMark,
			TunIfindex:    e.tunIfIndex,
			TunMac:        e.tunMAC,
			FakeIp4Prefix: e.fakeIP4Prefix,
			FakeIp6Prefix: *(*[2]uint32)(unsafe.Pointer(&e.fakeIP6Prefix)),
		}
		if err = objs.ParamsMap.Update(uint32(0), params, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update params map value: %w", err)
		}

		defer func() {
			_ = objs.TcTunFunc.Close()
			_ = objs.Close()
		}()

		prog = objs.TcTunFunc
	}

	if version.AtLeast(6, 6) { // `bpf_link` requires kernel >= v6.6
		linkEgress, err := link.AttachTCX(link.TCXOptions{
			Interface: e.ifIndex,
			Program:   prog,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			return fmt.Errorf("could not attach TCx egress program: %w", err)
		}
		e.link = linkEgress
	} else {
		qdisc := &netlink.GenericQdisc{
			QdiscType: "clsact",
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: e.ifIndex,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
		}
		e.qdisc = qdisc

		if err = netlink.QdiscAdd(qdisc); err != nil {
			if os.IsExist(err) {
				_ = netlink.QdiscDel(qdisc)
				err = netlink.QdiscAdd(qdisc)
			}
			if err != nil {
				e.Close()
				return fmt.Errorf("could not add clsact qdisc: %w", err)
			}
		}

		filter := &netlink.BpfFilter{
			Fd:           prog.FD(),
			Name:         "clash-tc-" + e.ifName,
			DirectAction: true,
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: e.ifIndex,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    netlink.MakeHandle(0, 1),
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			},
		}
		e.filter = filter

		if err = netlink.FilterAdd(filter); err != nil {
			e.Close()
			return fmt.Errorf("could not attach tc egress program: %w", err)
		}
	}

	return nil
}

func (e *EBpfTC) Close() {
	if e.link != nil {
		_ = e.link.Close()
	}
	if e.filter != nil {
		_ = netlink.FilterDel(e.filter)
	}
	if e.qdisc != nil {
		_ = netlink.QdiscDel(e.qdisc)
	}
}

func (e *EBpfTC) Lookup(_ netip.AddrPort) (netip.AddrPort, error) {
	return netip.AddrPort{}, fmt.Errorf("not supported")
}

func (e *EBpfTC) LookupUDP(_ netip.AddrPort) (netip.AddrPort, error) {
	return netip.AddrPort{}, fmt.Errorf("not supported")
}
