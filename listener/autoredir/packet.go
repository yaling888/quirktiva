package autoredir

import (
	"net"
	"net/netip"

	"github.com/yaling888/quirktiva/common/pool"
)

type packet struct {
	pc      *net.UDPConn
	rAddr   netip.AddrPort
	payload *[]byte
}

func (c *packet) Data() *[]byte {
	return c.payload
}

// WriteBack write UDP packet with source(ip, port) = `addr`
func (c *packet) WriteBack(b []byte, _ net.Addr) (n int, err error) {
	return c.pc.WriteToUDPAddrPort(b, c.rAddr)
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.rAddr)
}

func (c *packet) Drop() {
	pool.PutNetBuf(c.payload)
	c.payload = nil
}
