package inbound

import (
	"net"
	"net/http"
	"net/netip"

	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/context"
)

// NewHTTPS receive CONNECT request and return ConnContext
func NewHTTPS(request *http.Request, conn net.Conn) *context.ConnContext {
	metadata := parseHTTPAddr(request)
	metadata.Type = C.HTTPCONNECT
	if ip, port, err := parseAddr(conn.RemoteAddr()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = C.Port(port)
	}
	if ip, port, err := parseAddr(conn.LocalAddr()); err == nil {
		metadata.OriginDst = netip.AddrPortFrom(ip, uint16(port))
	}
	return context.NewConnContext(conn, metadata)
}
