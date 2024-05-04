package sniffer

import (
	"bytes"
	"io"
	"net"
	"time"
)

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) {
	return 0, io.EOF
}

var _ net.Conn = (*multiReaderConn)(nil)

type multiReaderConn struct {
	net.Conn
	r io.Reader
}

func (m *multiReaderConn) Read(b []byte) (n int, err error) {
	r := m.r
	if r == nil {
		return m.Conn.Read(b)
	}
	n, err = r.Read(b)
	if err == io.EOF {
		m.r = nil
		err = nil
		if n == 0 {
			n, err = m.Conn.Read(b)
		}
	}
	return
}

var _ net.Conn = (*backwardConn)(nil)

type backwardConn struct {
	c net.Conn
	r io.Reader
	b *bytes.Buffer
}

func (b *backwardConn) Read(p []byte) (n int, err error) {
	r := b.r
	return r.Read(p)
}

func (b *backwardConn) Write(_ []byte) (n int, err error) {
	return 0, net.ErrClosed
}

func (b *backwardConn) UnreadConn() net.Conn {
	b.r = eofReader{}
	_ = b.c.SetReadDeadline(time.Now())
	c := b.c
	r := b.b
	_ = b.c.SetReadDeadline(time.Time{})
	return &multiReaderConn{Conn: c, r: r}
}

func (b *backwardConn) Close() error {
	return nil
}

func (b *backwardConn) LocalAddr() net.Addr {
	return b.c.LocalAddr()
}

func (b *backwardConn) RemoteAddr() net.Addr {
	return b.c.RemoteAddr()
}

func (b *backwardConn) SetDeadline(t time.Time) error {
	return b.c.SetDeadline(t)
}

func (b *backwardConn) SetReadDeadline(t time.Time) error {
	return b.c.SetReadDeadline(t)
}

func (b *backwardConn) SetWriteDeadline(t time.Time) error {
	return b.c.SetWriteDeadline(t)
}

type ReadOnlyConn struct {
	*backwardConn
}

func StreamReadOnlyConn(conn net.Conn) *ReadOnlyConn {
	if c, ok := conn.(*ReadOnlyConn); ok {
		conn = c.UnreadConn()
	}
	rw := &bytes.Buffer{}
	return &ReadOnlyConn{backwardConn: &backwardConn{c: conn, r: io.TeeReader(conn, rw), b: rw}}
}
