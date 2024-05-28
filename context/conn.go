package context

import (
	"net"

	"github.com/yaling888/quirktiva/common/uuid"
	C "github.com/yaling888/quirktiva/constant"
)

type ConnContext struct {
	id       uuid.UUID
	metadata *C.Metadata
	conn     net.Conn
}

func NewConnContext(conn net.Conn, metadata *C.Metadata) *ConnContext {
	id := uuid.RandomB64Hlf()
	return &ConnContext{
		id:       id,
		metadata: metadata,
		conn:     conn,
	}
}

// ID implement C.ConnContext ID
func (c *ConnContext) ID() uuid.UUID {
	return c.id
}

// Metadata implement C.ConnContext Metadata
func (c *ConnContext) Metadata() *C.Metadata {
	return c.metadata
}

// Conn implement C.ConnContext Conn
func (c *ConnContext) Conn() net.Conn {
	return c.conn
}

// InjectConn implement C.ConnContext InjectConn
func (c *ConnContext) InjectConn(conn net.Conn) {
	c.conn = conn
}
