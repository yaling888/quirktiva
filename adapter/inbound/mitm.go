package inbound

import (
	"net"
	"net/netip"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/transport/socks5"
)

// NewMitm receive mitm request and return MitmContext
func NewMitm(target socks5.Addr, source net.Addr, originTarget net.Addr, userAgent string, specialProxy string, conn net.Conn) *context.ConnContext {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.TCP
	metadata.Type = C.MITM
	metadata.UserAgent = userAgent
	metadata.SpecialProxy = specialProxy

	if ip, port, err := parseAddr(source.String()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = port
	}
	if originTarget != nil {
		if addrPort, err := netip.ParseAddrPort(originTarget.String()); err == nil {
			metadata.OriginDst = addrPort
		}
	}
	return context.NewConnContext(conn, metadata)
}
