package system

import (
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/bufferv2"

	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars/nat"
)

type packet struct {
	sender *nat.UDP
	lAddr  netip.AddrPort
	data   *bufferv2.View
}

func (pkt *packet) Data() []byte {
	if pkt.data == nil {
		return nil
	}
	return pkt.data.AsSlice()
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
	pkt.data.Release()
	pkt.data = nil
}
