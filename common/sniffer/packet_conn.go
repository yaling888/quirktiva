package sniffer

import (
	"bytes"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
)

type packetReader interface {
	ReadFrom([]byte) (int, net.Addr, error)
}

type eofPacketReader struct{}

func (eofPacketReader) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}

type bytesPacketReader struct {
	r *bytes.Buffer
	a net.Addr
}

func (r *bytesPacketReader) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = r.r.Read(p)
	addr = r.a
	return
}

func (r *bytesPacketReader) Write(p []byte) (n int, err error) {
	return r.r.Write(p)
}

type multiPacketReader struct {
	readers []packetReader
}

func (mr *multiPacketReader) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for len(mr.readers) > 0 {
		if len(mr.readers) == 1 {
			if r, ok := mr.readers[0].(*multiPacketReader); ok {
				mr.readers = r.readers
				continue
			}
		}
		n, addr, err = mr.readers[0].ReadFrom(p)
		if err == io.EOF {
			mr.readers[0] = eofPacketReader{}
			mr.readers = mr.readers[1:]
		}
		if n > 0 || err != io.EOF {
			if err == io.EOF && len(mr.readers) > 0 {
				err = nil
			}
			return
		}
	}
	return 0, nil, io.EOF
}

var _ net.PacketConn = (*multiReaderPacketConn)(nil)

type multiReaderPacketConn struct {
	net.PacketConn
	r packetReader
}

func (m *multiReaderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	r := m.r
	if r == nil {
		return m.PacketConn.ReadFrom(p)
	}
	n, addr, err = r.ReadFrom(p)
	if err == io.EOF {
		m.r = nil
		err = nil
		if n == 0 {
			n, addr, err = m.PacketConn.ReadFrom(p)
		}
	}
	return
}

func (m *multiReaderPacketConn) SetReadBuffer(bytes int) error {
	if c, ok := m.PacketConn.(*net.UDPConn); ok {
		return c.SetReadBuffer(bytes)
	}
	return syscall.EINVAL
}

func (m *multiReaderPacketConn) SetWriteBuffer(bytes int) error {
	if c, ok := m.PacketConn.(*net.UDPConn); ok {
		return c.SetWriteBuffer(bytes)
	}
	return syscall.EINVAL
}

var _ net.PacketConn = (*backwardPacketConn)(nil)

type backwardPacketConn struct {
	c net.PacketConn
	r packetReader

	wMux sync.Mutex
	wm   map[string]*bytesPacketReader
}

func (b *backwardPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	r := b.r
	n, addr, err = r.ReadFrom(p)
	if n > 0 && addr != nil {
		b.wMux.Lock()
		w := b.wm[addr.String()]
		if w == nil {
			w = &bytesPacketReader{
				r: &bytes.Buffer{},
				a: addr,
			}
			b.wm[addr.String()] = w
		}
		b.wMux.Unlock()
		_, _ = w.Write(p[:n])
	}
	return
}

func (b *backwardPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	n = len(p)
	return
}

func (b *backwardPacketConn) UnreadPacketConn() net.PacketConn {
	b.r = eofPacketReader{}
	_ = b.c.SetReadDeadline(time.Now())

	b.wMux.Lock()
	readers := make([]packetReader, 0, len(b.wm))
	for _, v := range b.wm {
		readers = append(readers, v)
	}
	clear(b.wm)
	b.wMux.Unlock()

	_ = b.c.SetReadDeadline(time.Time{})
	c := b.c
	return &multiReaderPacketConn{PacketConn: c, r: &multiPacketReader{readers: readers}}
}

func (*backwardPacketConn) Close() error {
	return nil
}

func (b *backwardPacketConn) LocalAddr() net.Addr {
	return b.c.LocalAddr()
}

func (b *backwardPacketConn) SetDeadline(t time.Time) error {
	return b.c.SetDeadline(t)
}

func (b *backwardPacketConn) SetReadDeadline(t time.Time) error {
	return b.c.SetReadDeadline(t)
}

func (b *backwardPacketConn) SetWriteDeadline(t time.Time) error {
	return b.c.SetWriteDeadline(t)
}

func (b *backwardPacketConn) SetReadBuffer(_ int) error  { return nil }
func (b *backwardPacketConn) SetWriteBuffer(_ int) error { return nil }

type ReadOnlyPacketConn struct {
	*backwardPacketConn
}

func StreamReadOnlyPacketConn(conn net.PacketConn) *ReadOnlyPacketConn {
	if c, ok := conn.(*ReadOnlyPacketConn); ok {
		conn = c.UnreadPacketConn()
	}
	return &ReadOnlyPacketConn{
		backwardPacketConn: &backwardPacketConn{
			c:  conn,
			r:  conn,
			wm: make(map[string]*bytesPacketReader),
		},
	}
}
