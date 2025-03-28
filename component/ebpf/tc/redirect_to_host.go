//go:build linux

package tc

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/yaling888/quirktiva/common/hostos"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpf -tags linux tun_redir_to_host ../bpf/tun_redir_to_host.ebpf.c

type HostObj struct {
	IFIndex uint32
	MAC     [6]byte
}

type EBpfRTH struct {
	link   link.Link
	qdisc  netlink.Qdisc
	filter netlink.Filter

	ifIndex  int
	hostObjs []HostObj
}

func NewEBpfRTH(ifIndex int, hostObjs []HostObj) *EBpfRTH {
	return &EBpfRTH{
		ifIndex:  ifIndex,
		hostObjs: hostObjs,
	}
}

func (e *EBpfRTH) Start() error {
	version := hostos.KernelVersion()
	if version.LessThan(5, 11) { // remove resource limits for kernels < v5.11.
		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("remove memory lock: %w", err)
		}
	}

	objs := tun_redir_to_hostObjects{}
	if err := loadTun_redir_to_hostObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	defer func() {
		_ = objs.Close()
	}()

	for _, o := range e.hostObjs {
		if err := objs.HostsMap.Update(o.MAC, o.IFIndex, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update hosts map value: %w", err)
		}
	}

	if version.AtLeast(6, 6) { // `bpf_link` requires kernel >= v6.6
		linkIngress, err := link.AttachTCX(link.TCXOptions{
			Interface: e.ifIndex,
			Program:   objs.TcTunRedirectToHost,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			return fmt.Errorf("could not attach TCx ingress program: %w", err)
		}
		e.link = linkIngress
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

		if err := netlink.QdiscAdd(qdisc); err != nil {
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
			Fd:           objs.TcTunRedirectToHost.FD(),
			Name:         "clash_tun_redir_to_host",
			DirectAction: true,
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: e.ifIndex,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    netlink.MakeHandle(0, 1),
				Protocol:  unix.ETH_P_ALL,
				Priority:  0,
			},
		}
		e.filter = filter

		if err := netlink.FilterAdd(filter); err != nil {
			e.Close()
			return fmt.Errorf("could not attach tc ingress program: %w", err)
		}
	}

	return nil
}

func (e *EBpfRTH) Close() {
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

func (e *EBpfRTH) Lookup(_ netip.AddrPort) (netip.AddrPort, error) {
	return netip.AddrPort{}, fmt.Errorf("not supported")
}

func (e *EBpfRTH) LookupUDP(_ netip.AddrPort) (netip.AddrPort, error) {
	return netip.AddrPort{}, fmt.Errorf("not supported")
}
