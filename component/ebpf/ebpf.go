package ebpf

import (
	"net/netip"

	"github.com/Dreamacro/clash/common/cmd"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

type option struct {
	ipv6           bool
	sysAllIPv6     string
	sysDefaultIPv6 string
}

type TcEBpfProgram struct {
	opt          *option
	pros         []C.EBpf
	rawNICs      []string
	rawInterface string
}

func (t *TcEBpfProgram) RawNICs() []string {
	return t.rawNICs
}

func (t *TcEBpfProgram) RawInterface() string {
	return t.rawInterface
}

func (t *TcEBpfProgram) Close() {
	for _, p := range t.pros {
		p.Close()
	}

	resolver.DisableIPv6 = t.opt.ipv6

	//if t.opt.sysAllIPv6 != "" {
	//	_, _ = cmd.ExecCmd("sysctl -w net.ipv6.conf.all.disable_ipv6=" + t.opt.sysAllIPv6)
	//}
	//if t.opt.sysDefaultIPv6 != "" {
	//	_, _ = cmd.ExecCmd("sysctl -w net.ipv6.conf.default.disable_ipv6=" + t.opt.sysDefaultIPv6)
	//}
}

func (t *TcEBpfProgram) Lookup(srcAddrPort netip.AddrPort) (addr socks5.Addr, err error) {
	for _, p := range t.pros {
		addr, err = p.Lookup(srcAddrPort)
		if err == nil {
			return
		}
	}
	return
}

func NewAutoRedirProgram(pros []C.EBpf, rawNICs []string, rawInterface string) *TcEBpfProgram {
	var (
		sysAllIPv6, _     = cmd.ExecCmd("cat /proc/sys/net/ipv6/conf/all/disable_ipv6")
		sysDefaultIPv6, _ = cmd.ExecCmd("cat /proc/sys/net/ipv6/conf/default/disable_ipv6")
	)

	opt := &option{
		ipv6:           resolver.DisableIPv6,
		sysAllIPv6:     sysAllIPv6,
		sysDefaultIPv6: sysDefaultIPv6,
	}

	resolver.DisableIPv6 = true

	//_, _ = cmd.ExecCmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
	//_, _ = cmd.ExecCmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")

	return &TcEBpfProgram{
		opt:          opt,
		pros:         pros,
		rawNICs:      rawNICs,
		rawInterface: rawInterface,
	}
}
