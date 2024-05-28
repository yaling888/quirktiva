package inbound

import (
	"net"
	"net/netip"

	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/context"
	"github.com/yaling888/quirktiva/transport/socks5"
)

// NewSocket receive TCP inbound and return ConnContext
func NewSocket(target socks5.Addr, conn net.Conn, source C.Type) *context.ConnContext {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.TCP
	metadata.Type = source
	if ip, port, err := parseAddr(conn.RemoteAddr()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = C.Port(port)
	}
	if ip, port, err := parseAddr(conn.LocalAddr()); err == nil {
		metadata.OriginDst = netip.AddrPortFrom(ip, uint16(port))
	}
	return context.NewConnContext(conn, metadata)
}

// NewSocketBy receive TCP inbound and return ConnContext
func NewSocketBy(conn net.Conn, src, dst netip.AddrPort, tp C.Type) *context.ConnContext {
	metadata := &C.Metadata{}
	metadata.NetWork = C.TCP
	metadata.Type = tp
	metadata.SrcIP = src.Addr()
	metadata.SrcPort = C.Port(src.Port())
	metadata.DstIP = dst.Addr()
	metadata.DstPort = C.Port(dst.Port())
	metadata.OriginDst = dst

	return context.NewConnContext(conn, metadata)
}
