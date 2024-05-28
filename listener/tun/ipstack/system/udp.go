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
	a := addr.(*net.UDPAddr)
	na, _ := netip.AddrFromSlice(a.IP)
	na = na.WithZone(a.Zone)
	if pkt.lAddr.Addr().Is4() {
		na = na.Unmap()
	}
	return pkt.sender.WriteTo(b, netip.AddrPortFrom(na, uint16(a.Port)), pkt.lAddr)
}

func (pkt *packet) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(pkt.lAddr)
}

func (pkt *packet) Drop() {
	pkt.sender.PutUDPElement(pkt.data)
	pkt.data = nil
}
