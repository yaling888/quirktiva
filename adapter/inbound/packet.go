package inbound

import (
	"net/netip"
	"strconv"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
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
func NewPacket(target socks5.Addr, packet C.UDPPacket, source C.Type) *PacketAdapter {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.UDP
	metadata.Type = source
	if ip, port, err := parseAddr(packet.LocalAddr().String()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = port
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
	metadata.SrcPort = strconv.FormatUint(uint64(src.Port()), 10)
	metadata.DstIP = dst.Addr()
	metadata.DstPort = strconv.FormatUint(uint64(dst.Port()), 10)

	return &PacketAdapter{
		UDPPacket: packet,
		metadata:  metadata,
	}
}
