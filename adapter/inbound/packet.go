package inbound

import (
	"net"
	"net/netip"

	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/socks5"
)

// PacketAdapter is a UDP Packet adapter for socks/redir/tun
type PacketAdapter struct {
	C.UDPPacket
	metadata *C.Metadata
}

// Metadata returns destination metadata
func (s *PacketAdapter) Metadata() *C.Metadata {
	return s.metadata
}

// NewPacket is PacketAdapter generator
func NewPacket(target socks5.Addr, originTarget net.Addr, packet C.UDPPacket, source C.Type) *PacketAdapter {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.UDP
	metadata.Type = source
	if ip, port, err := parseAddr(packet.LocalAddr()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = C.Port(port)
	}
	if ip, port, err := parseAddr(originTarget); err == nil {
		metadata.OriginDst = netip.AddrPortFrom(ip, uint16(port))
	}
	return &PacketAdapter{
		UDPPacket: packet,
		metadata:  metadata,
	}
}

// NewPacketBy is PacketAdapter generator
func NewPacketBy(packet C.UDPPacket, src, dst netip.AddrPort, tp C.Type) *PacketAdapter {
	metadata := &C.Metadata{}
	metadata.NetWork = C.UDP
	metadata.Type = tp
	metadata.SrcIP = src.Addr()
	metadata.SrcPort = C.Port(src.Port())
	metadata.DstIP = dst.Addr()
	metadata.DstPort = C.Port(dst.Port())
	metadata.OriginDst = dst

	return &PacketAdapter{
		UDPPacket: packet,
		metadata:  metadata,
	}
}
