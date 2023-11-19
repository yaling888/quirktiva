package vless

import (
	"errors"
	"io"
	"net"

	"github.com/yaling888/clash/common/pool"
	"github.com/yaling888/clash/common/uuid"
)

type Conn struct {
	net.Conn
	dst      *DstAddr
	id       uuid.UUID
	received bool
}

func (vc *Conn) Read(b []byte) (int, error) {
	if vc.received {
		return vc.Conn.Read(b)
	}

	if err := vc.recvResponse(); err != nil {
		return 0, err
	}
	vc.received = true
	return vc.Conn.Read(b)
}

func (vc *Conn) sendRequest() error {
	buf := pool.BufferWriter{}

	buf.PutUint8(Version)       // protocol version
	buf.PutSlice(vc.id.Bytes()) // 16 bytes of uuid
	buf.PutUint8(0)             // addon data length. 0 means no addon data
	// buf.PutString("")           // addon data

	// Command
	if vc.dst.UDP {
		buf.PutUint8(CommandUDP)
	} else {
		buf.PutUint8(CommandTCP)
	}

	// Port AddrType Addr
	buf.PutUint16be(uint16(vc.dst.Port))
	buf.PutUint8(vc.dst.AddrType)
	buf.PutSlice(vc.dst.Addr)

	_, err := vc.Conn.Write(buf.Bytes())
	return err
}

func (vc *Conn) recvResponse() error {
	var buf [2]byte
	if _, err := io.ReadFull(vc.Conn, buf[:]); err != nil {
		return err
	}

	if buf[0] != Version {
		return errors.New("unexpected response version")
	}

	length := int64(buf[1])
	if length > 0 { // addon data length > 0
		_, _ = io.CopyN(io.Discard, vc.Conn, length) // just discard
	}

	return nil
}

// newConn return a Conn instance
func newConn(conn net.Conn, client *Client, dst *DstAddr) (*Conn, error) {
	c := &Conn{
		Conn: conn,
		id:   client.uuid,
		dst:  dst,
	}

	if err := c.sendRequest(); err != nil {
		return nil, err
	}
	return c, nil
}
