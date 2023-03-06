package system

import (
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/bufferv2"
)

type packet struct {
	local     netip.AddrPort
	data      *bufferv2.View
	writeBack func(b []byte, addr net.Addr) (int, error)
}

func (pkt *packet) Data() []byte {
	return pkt.data.AsSlice()
}

func (pkt *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	return pkt.writeBack(b, addr)
}

func (pkt *packet) Drop() {
	pkt.data.Release()
	pkt.data = nil
}

func (pkt *packet) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(pkt.local)
}
