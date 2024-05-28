package socks

import (
	"net"

	"github.com/yaling888/quirktiva/common/pool"
	"github.com/yaling888/quirktiva/transport/socks5"
)

type packet struct {
	pc      net.PacketConn
	rAddr   net.Addr
	payload *[]byte
}

func (c *packet) Data() *[]byte {
	return c.payload
}

// WriteBack write UDP packet with source(ip, port) = `addr`
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	return c.pc.WriteTo(packet, c.rAddr)
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return c.rAddr
}

func (c *packet) Drop() {
	pool.PutNetBuf(c.payload)
	c.payload = nil
}
