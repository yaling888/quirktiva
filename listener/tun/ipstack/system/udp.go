package system

import (
	"net"
	"net/netip"

	"github.com/yaling888/quirktiva/listener/tun/ipstack/system/mars/nat"
)

type packet struct {
	sender *nat.UDP
	data   *nat.UDPElement
	lAddr  netip.AddrPort
}

func (pkt *packet) Data() *[]byte {
	if pkt.data != nil {
		return pkt.data.Packet
	}
	return nil
}

func (pkt *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	if a, ok := addr.(*net.UDPAddr); ok {
		return pkt.sender.WriteTo(b, a.AddrPort(), pkt.lAddr)
	}
	return 0, net.InvalidAddrError("not an udp address")
}

func (pkt *packet) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(pkt.lAddr)
}

func (pkt *packet) Drop() {
	pkt.sender.PutUDPElement(pkt.data)
	pkt.data = nil
}
