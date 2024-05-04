package constant

import (
	"net"

	"github.com/yaling888/clash/common/uuid"
)

type PlainContext interface {
	ID() uuid.UUID
}

type ConnContext interface {
	PlainContext
	Metadata() *Metadata
	Conn() net.Conn
	InjectConn(conn net.Conn)
}

type PacketConnContext interface {
	PlainContext
	Metadata() *Metadata
	PacketConn() net.PacketConn
}
