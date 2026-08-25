package sniffer

import (
	"io"
	"math/rand/v2"
	"net"
	"time"
)

type readError string

func (e readError) Error() string   { return string(e) }
func (e readError) Timeout() bool   { return true }
func (e readError) Temporary() bool { return true }

var _ net.PacketConn = (*ReadOnlyPacketConn)(nil)

type ReadOnlyPacketConn struct {
	r     io.Reader
	lAddr net.Addr
	rAddr net.Addr
}

func (c *ReadOnlyPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.r.Read(p)
	addr = c.rAddr
	if err != nil {
		if ne, ok := err.(net.Error); !ok || !ne.Temporary() { //nolint:staticcheck
			err = readError(err.Error())
		}
	}
	return
}

func (c *ReadOnlyPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return len(p), nil
}

func (c *ReadOnlyPacketConn) LocalAddr() net.Addr {
	return c.lAddr
}

func (c *ReadOnlyPacketConn) Close() error {
	if e, ok := c.r.(io.Closer); ok {
		return e.Close()
	}
	c.r = eofReader{}
	return nil
}

func (c *ReadOnlyPacketConn) SetDeadline(t time.Time) error {
	if d, ok := c.r.(interface{ SetDeadline(time.Time) error }); ok {
		return d.SetDeadline(t)
	}
	return nil
}

func (c *ReadOnlyPacketConn) SetReadDeadline(t time.Time) error {
	if d, ok := c.r.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

func (c *ReadOnlyPacketConn) SetWriteDeadline(t time.Time) error {
	if d, ok := c.r.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}

func (c *ReadOnlyPacketConn) SetReadBuffer(_ int) error  { return nil }
func (c *ReadOnlyPacketConn) SetWriteBuffer(_ int) error { return nil }

func NewReadOnlyPacketConn(r io.Reader) *ReadOnlyPacketConn {
	return &ReadOnlyPacketConn{
		r:     r,
		lAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12000 + rand.IntN(5000)},
		rAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 17000 + rand.IntN(5000)},
	}
}
