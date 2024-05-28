package context

import (
	"net"

	"github.com/yaling888/quirktiva/common/uuid"
	C "github.com/yaling888/quirktiva/constant"
)

type PacketConnContext struct {
	id         uuid.UUID
	metadata   *C.Metadata
	packetConn net.PacketConn
}

func NewPacketConnContext(metadata *C.Metadata) *PacketConnContext {
	id := uuid.RandomB64Hlf()
	return &PacketConnContext{
		id:       id,
		metadata: metadata,
	}
}

// ID implement C.PacketConnContext ID
func (pc *PacketConnContext) ID() uuid.UUID {
	return pc.id
}

// Metadata implement C.PacketConnContext Metadata
func (pc *PacketConnContext) Metadata() *C.Metadata {
	return pc.metadata
}

// PacketConn implement C.PacketConnContext PacketConn
func (pc *PacketConnContext) PacketConn() net.PacketConn {
	return pc.packetConn
}

// InjectPacketConn manually
func (pc *PacketConnContext) InjectPacketConn(pConn C.PacketConn) {
	pc.packetConn = pConn
}
