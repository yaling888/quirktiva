package pool

import (
	"bytes"
	"io"
)

type Buffer struct {
	buf *bytes.Buffer
}

func NewBuffer() Buffer {
	return Buffer{
		buf: GetBuffer(),
	}
}

func (b *Buffer) Release() {
	PutBuffer(b.buf)
	b.buf = nil
}

func (b Buffer) Reset() {
	b.buf.Reset()
}

func (b Buffer) Grow(n int) {
	b.buf.Grow(n)
}

func (b Buffer) Len() int {
	return b.buf.Len()
}

func (b Buffer) Cap() int {
	return b.buf.Cap()
}

func (b Buffer) Read(p []byte) (n int, err error) {
	return b.buf.Read(p)
}

func (b Buffer) ReadByte() (byte, error) {
	return b.buf.ReadByte()
}

func (b Buffer) ReadFrom(r io.Reader) (n int64, err error) {
	return b.buf.ReadFrom(r)
}

func (b Buffer) ReadFullFrom(r io.Reader, size int64) (n int64, err error) {
	n, err = b.buf.ReadFrom(io.LimitReader(r, size))
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
		return
	}
	return
}

func (b Buffer) Write(p []byte) (n int, err error) {
	return b.buf.Write(p)
}

func (b Buffer) WriteTo(w io.Writer) (n int64, err error) {
	return b.buf.WriteTo(w)
}

func (b Buffer) Next(n int) []byte {
	return b.buf.Next(n)
}

func (b Buffer) Bytes() []byte {
	return b.buf.Bytes()
}
