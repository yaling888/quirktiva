package inbound

import (
	"net"
	"net/netip"
	"strconv"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/transport/socks5"
)

// NewSocket receive TCP inbound and return ConnContext
func NewSocket(target socks5.Addr, conn net.Conn, source C.Type) *context.ConnContext {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.TCP
	metadata.Type = source
	if ip, port, err := parseAddr(conn.RemoteAddr().String()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = port
	}

	return context.NewConnContext(conn, metadata)
}

// NewSocketBy receive TCP inbound and return ConnContext
func NewSocketBy(conn net.Conn, src, dst netip.AddrPort, tp C.Type) *context.ConnContext {
	metadata := &C.Metadata{}
	metadata.NetWork = C.TCP
	metadata.Type = tp
	metadata.SrcIP = src.Addr()
	metadata.SrcPort = strconv.FormatUint(uint64(src.Port()), 10)
	metadata.DstIP = dst.Addr()
	metadata.DstPort = strconv.FormatUint(uint64(dst.Port()), 10)

	return context.NewConnContext(conn, metadata)
}
