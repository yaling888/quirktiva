package tproxy

import (
	"net"
	"net/netip"

	"github.com/Dreamacro/clash/common/pool"
)

type packet struct {
	lAddr netip.AddrPort
	buf   []byte
}

func (c *packet) Data() []byte {
	return c.buf
}

// WriteBack opens a new socket binding `addr` to write UDP packet back
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	rAddr := addr.(*net.UDPAddr).AddrPort()
	if c.lAddr.Addr().Is4() && rAddr.Addr().Is4In6() {
		rAddr = netip.AddrPortFrom(rAddr.Addr().Unmap(), rAddr.Port())
	}

	tc, err := dialUDP("udp", rAddr, c.lAddr)
	if err != nil {
		n = 0
		return
	}
	n, err = tc.Write(b)
	_ = tc.Close()
	return
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.lAddr)
}

func (c *packet) Drop() {
	_ = pool.Put(c.buf)
}
