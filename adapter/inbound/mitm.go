package inbound

import (
	"net"
	"net/netip"

	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/context"
	"github.com/yaling888/quirktiva/transport/socks5"
)

// NewMitm receive mitm request and return MitmContext
func NewMitm(target socks5.Addr, source net.Addr, originTarget net.Addr, userAgent string, specialProxy string, conn net.Conn) *context.ConnContext {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.TCP
	metadata.Type = C.MITM
	metadata.UserAgent = userAgent
	metadata.SpecialProxy = specialProxy

	if ip, port, err := parseAddr(source); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = C.Port(port)
	}
	if ip, port, err := parseAddr(originTarget); err == nil {
		metadata.OriginDst = netip.AddrPortFrom(ip, uint16(port))
	}
	return context.NewConnContext(conn, metadata)
}
