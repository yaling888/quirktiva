package outboundgroup

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	C "github.com/yaling888/quirktiva/constant"
)

func addrToMetadata(rawAddress string) (addr *C.Metadata, err error) {
	host, port, err := net.SplitHostPort(rawAddress)
	if err != nil {
		err = fmt.Errorf("addrToMetadata failed: %w", err)
		return
	}

	ip, err := netip.ParseAddr(host)
	p, _ := strconv.ParseUint(port, 10, 16)
	if err != nil {
		addr = &C.Metadata{
			Host:    host,
			DstIP:   netip.Addr{},
			DstPort: C.Port(p),
		}
		return addr, nil
	} else if ip.Is4() {
		addr = &C.Metadata{
			Host:    "",
			DstIP:   ip,
			DstPort: C.Port(p),
		}
		return
	}

	addr = &C.Metadata{
		Host:    "",
		DstIP:   ip,
		DstPort: C.Port(p),
	}
	return
}

func tcpKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
}
