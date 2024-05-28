package obfs

import (
	R "crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"math/rand/v2"
	"net"

	"github.com/yaling888/quirktiva/common/pool"
)

func init() {
	register("random_head", newRandomHead, 0)
}

type randomHead struct {
	*Base
}

func newRandomHead(b *Base) Obfs {
	return &randomHead{Base: b}
}

type randomHeadConn struct {
	net.Conn
	*randomHead
	hasSentHeader bool
	rawTransSent  bool
	rawTransRecv  bool
	buf           []byte
}

func (r *randomHead) StreamConn(c net.Conn) net.Conn {
	return &randomHeadConn{Conn: c, randomHead: r}
}

func (c *randomHeadConn) Read(b []byte) (int, error) {
	if c.rawTransRecv {
		return c.Conn.Read(b)
	}
	bufP := pool.GetNetBuf()
	defer pool.PutNetBuf(bufP)
	_, _ = c.Conn.Read(*bufP)
	c.rawTransRecv = true
	_, _ = c.Write(nil)
	return 0, nil
}

func (c *randomHeadConn) Write(b []byte) (int, error) {
	if c.rawTransSent {
		return c.Conn.Write(b)
	}
	c.buf = append(c.buf, b...)
	if !c.hasSentHeader {
		c.hasSentHeader = true
		dataLength := rand.IntN(96) + 4
		bufP := pool.GetBufferWriter()
		bufP.Grow(dataLength + 4)
		defer pool.PutBufferWriter(bufP)
		_, _ = R.Read((*bufP)[:dataLength])
		binary.LittleEndian.PutUint32((*bufP)[dataLength:], 0xffffffff-crc32.ChecksumIEEE((*bufP)[:dataLength]))
		_, err := c.Conn.Write(bufP.Bytes())
		return len(b), err
	}
	if c.rawTransRecv {
		_, err := c.Conn.Write(c.buf)
		c.buf = nil
		c.rawTransSent = true
		return len(b), err
	}
	return len(b), nil
}
