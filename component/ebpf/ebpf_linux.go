package ebpf

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/yaling888/quirktiva/common/cmd"
	"github.com/yaling888/quirktiva/component/dialer"
	"github.com/yaling888/quirktiva/component/ebpf/redir"
	"github.com/yaling888/quirktiva/component/ebpf/tc"
	"github.com/yaling888/quirktiva/component/resolver"
	C "github.com/yaling888/quirktiva/constant"
)

// NewTcEBpfProgram new redirect to tun ebpf program
func NewTcEBpfProgram(ifaceNames []string, tunName string) (*TcEBpfProgram, error) {
	if _, a, f := strings.Cut(tunName, "://"); f && a != "" {
		tunName = a
	}
	tunIface, err := netlink.LinkByName(tunName)
	if err != nil {
		return nil, fmt.Errorf("lookup network iface %s: %w", tunName, err)
	}

	tunIndex := tunIface.Attrs().Index
	tunMAC := tunIface.Attrs().HardwareAddr

	dialer.DefaultRoutingMark.CompareAndSwap(0, C.ClashTrafficMark)

	ifMark := uint32(dialer.DefaultRoutingMark.Load())

	fakeIP4Prefix := resolver.FakeIP4Prefix()
	fakeIP6Prefix := resolver.FakeIP6Prefix()

	var hostObjs []tc.HostObj
	var pros []C.EBpf
	for _, ifaceName := range ifaceNames {
		iface, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("lookup network iface %s: %w", ifaceName, err)
		}
		if (iface.Attrs().Flags & net.FlagUp) == 0 {
			return nil, fmt.Errorf("network iface %s is down", ifaceName)
		}

		attrs := iface.Attrs()
		index := attrs.Index
		mac := attrs.HardwareAddr

		tcPro := tc.NewEBpfTc(ifaceName, index, ifMark, uint32(tunIndex), tunMAC, fakeIP4Prefix, fakeIP6Prefix)
		if err = tcPro.Start(); err != nil {
			return nil, err
		}

		if len(mac) == 6 {
			hostObjs = append(hostObjs, tc.HostObj{
				IFIndex: uint32(index),
				MAC:     [6]byte(mac),
			})
		}

		pros = append(pros, tcPro)
	}

	if len(tunMAC) == 6 && len(hostObjs) > 0 {
		tcPro := tc.NewEBpfRTH(tunIndex, hostObjs)
		if err = tcPro.Start(); err != nil {
			for _, p := range pros {
				p.Close()
			}
			return nil, err
		}
		pros = append(pros, tcPro)
	}

	systemSetting(ifaceNames...)

	return &TcEBpfProgram{pros: pros, rawNICs: ifaceNames}, nil
}

// NewRedirEBpfProgram new auto redirect ebpf program
func NewRedirEBpfProgram(ifaceNames []string, redirPort uint16) (*TcEBpfProgram, error) {
	fakeIP4Prefix := resolver.FakeIP4Prefix()
	fakeIP6Prefix := resolver.FakeIP6Prefix()

	var pros []C.EBpf
	for _, ifaceName := range ifaceNames {
		iface, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("lookup network iface %s: %w", ifaceName, err)
		}

		attrs := iface.Attrs()
		index := attrs.Index

		addrs, err := netlink.AddrList(iface, netlink.FAMILY_ALL)
		if err != nil {
			return nil, fmt.Errorf("lookup network iface %s address: %w", ifaceName, err)
		}

		var addr4, addr6 netip.Addr
		for _, addr := range addrs {
			if ip := addr.IP.To4(); ip != nil {
				if !addr4.IsValid() {
					addr4, _ = netip.AddrFromSlice(ip)
				}
			} else if !addr6.IsValid() {
				addr6, _ = netip.AddrFromSlice(addr.IP)
			}
		}

		if !addr4.IsValid() {
			return nil, fmt.Errorf("network iface %s does not contain any ipv4 addresses", ifaceName)
		}

		if !addr6.IsValid() {
			addr6 = addr4
		}

		redirAddrPort := netip.AddrPortFrom(addr4, redirPort)

		redirPro := redir.NewEBpfRedirect(ifaceName, index, redirAddrPort, addr6, fakeIP4Prefix, fakeIP6Prefix)
		if err = redirPro.Start(); err != nil {
			return nil, err
		}

		pros = append(pros, redirPro)
	}

	systemSetting(ifaceNames...)

	return NewAutoRedirProgram(pros, ifaceNames), nil
}

func systemSetting(ifaceNames ...string) {
	_, _ = cmd.ExecCmd("sysctl -w net.ipv4.ip_forward=1")
	_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.forwarding=1")
	_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.accept_local=1")
	_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.accept_redirects=1")
	_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
	_, _ = cmd.ExecCmd("sysctl -w net.ipv6.conf.all.forwarding=1")
	_, _ = cmd.ExecCmd("sysctl -w net.ipv6.conf.all.accept_redirects=1")
	_, _ = cmd.ExecCmd("iptables -t filter -P FORWARD ACCEPT")

	for _, ifaceName := range ifaceNames {
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.forwarding=1", ifaceName))
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.accept_local=1", ifaceName))
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.accept_redirects=1", ifaceName))
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.rp_filter=0", ifaceName))
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv6.conf.%s.forwarding=1", ifaceName))
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv6.conf.%s.accept_redirects=1", ifaceName))
	}
}
