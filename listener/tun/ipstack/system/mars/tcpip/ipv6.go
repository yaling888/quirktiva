package tcpip

import (
	"encoding/binary"
	"net/netip"
)

const (
	versTCFL = 0

	IPv6PayloadLenOffset = 4

	IPv6NextHeaderOffset = 6
	hopLimit             = 7
	v6SrcAddr            = 8
	v6DstAddr            = v6SrcAddr + IPv6AddressSize

	IPv6FixedHeaderSize = v6DstAddr + IPv6AddressSize
)

const (
	versIHL        = 0
	tos            = 1
	ipVersionShift = 4
	ipIHLMask      = 0x0f
	IPv4IHLStride  = 4

	ipv6ExtHdrLenBytesPerUnit = 8
)

const (
	ipv6HopByHopOptionsExtHdrIdentifier    uint8 = 0
	ipv6RoutingExtHdrIdentifier            uint8 = 43
	ipv6FragmentExtHdrIdentifier           uint8 = 44
	ipv6DestinationOptionsExtHdrIdentifier uint8 = 60
	ipv6NoNextHeaderIdentifier             uint8 = 59
	ipv6ExperimentExtHdrIdentifier         uint8 = 253
	ipv6UnknownExtHdrIdentifier            uint8 = 254
)

type IPv6Packet []byte

const (
	IPv6MinimumSize = IPv6FixedHeaderSize

	IPv6AddressSize = 16

	IPv6Version = 6

	IPv6MinimumMTU = 1280
)

func (b IPv6Packet) PayloadLength() uint16 {
	return binary.BigEndian.Uint16(b[IPv6PayloadLenOffset:])
}

func (b IPv6Packet) HopLimit() uint8 {
	return b[hopLimit]
}

func (b IPv6Packet) NextHeader() byte {
	return b[IPv6NextHeaderOffset]
}

func (b IPv6Packet) Protocol() IPProtocol {
	hdr, _ := b.lastNextHeader()
	return hdr
}

func (b IPv6Packet) Payload() []byte {
	_, offset := b.lastNextHeader()
	payloadLen := int(b.PayloadLength()) - offset + IPv6FixedHeaderSize
	return b[offset:][:payloadLen]
}

func (b IPv6Packet) SourceIP() netip.Addr {
	addr, _ := netip.AddrFromSlice(b[v6SrcAddr:][:IPv6AddressSize])
	return addr
}

func (b IPv6Packet) DestinationIP() netip.Addr {
	addr, _ := netip.AddrFromSlice(b[v6DstAddr:][:IPv6AddressSize])
	return addr
}

func (IPv6Packet) Checksum() uint16 {
	return 0
}

func (b IPv6Packet) TOS() (uint8, uint32) {
	v := binary.BigEndian.Uint32(b[versTCFL:])
	return uint8(v >> 20), v & 0xfffff
}

func (b IPv6Packet) SetTOS(t uint8, l uint32) {
	vtf := (6 << 28) | (uint32(t) << 20) | (l & 0xfffff)
	binary.BigEndian.PutUint32(b[versTCFL:], vtf)
}

func (b IPv6Packet) SetPayloadLength(payloadLength uint16) {
	binary.BigEndian.PutUint16(b[IPv6PayloadLenOffset:], payloadLength)
}

func (b IPv6Packet) SetSourceIP(addr netip.Addr) {
	a := addr.As16()
	copy(b[v6SrcAddr:][:IPv6AddressSize], a[:])
}

func (b IPv6Packet) SetDestinationIP(addr netip.Addr) {
	a := addr.As16()
	copy(b[v6DstAddr:][:IPv6AddressSize], a[:])
}

func (b IPv6Packet) SetHopLimit(v uint8) {
	b[hopLimit] = v
}

func (b IPv6Packet) SetNextHeader(v byte) {
	b[IPv6NextHeaderOffset] = v
}

func (b IPv6Packet) SetProtocol(p IPProtocol) {
	b.SetNextHeader(p)
}

func (b IPv6Packet) DecTimeToLive() {
	b[hopLimit] = b[hopLimit] - uint8(1)
}

func (IPv6Packet) SetChecksum(uint16) {
}

func (IPv6Packet) ResetChecksum() {
}

func (b IPv6Packet) PseudoSum() uint32 {
	protocol, offset := b.lastNextHeader()
	payloadLen := int(b.PayloadLength()) - offset + IPv6FixedHeaderSize
	sum := Sum(b[v6SrcAddr:IPv6FixedHeaderSize])
	sum += uint32(protocol)
	sum += uint32(payloadLen)
	return sum
}

func (b IPv6Packet) Valid() bool {
	if len(b) < IPv6MinimumSize {
		return false
	}

	dlen := int(b.PayloadLength())
	if dlen > len(b)-IPv6MinimumSize {
		return false
	}

	return true
}

func (b IPv6Packet) lastNextHeader() (uint8, int) {
	hdr := b[IPv6NextHeaderOffset]
	return b.nextExtensionHeader(hdr, IPv6FixedHeaderSize)
}

func (b IPv6Packet) nextExtensionHeader(hdr uint8, offset int) (uint8, int) {
	switch hdr {
	case ipv6HopByHopOptionsExtHdrIdentifier,
		ipv6RoutingExtHdrIdentifier,
		//ipv6FragmentExtHdrIdentifier,
		//ipv6NoNextHeaderIdentifier,
		ipv6DestinationOptionsExtHdrIdentifier,
		ipv6ExperimentExtHdrIdentifier:
		id := b[offset]
		length := b[offset+1]
		offset += int((length + 1) * ipv6ExtHdrLenBytesPerUnit)
		return b.nextExtensionHeader(id, offset)
	}
	return hdr, offset
}

func IPVersion(b []byte) int {
	if len(b) < versIHL+1 {
		return -1
	}
	return int(b[versIHL] >> ipVersionShift)
}

var _ IP = (*IPv6Packet)(nil)
