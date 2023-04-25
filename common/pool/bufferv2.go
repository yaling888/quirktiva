package pool

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"unicode/utf8"

	"github.com/Dreamacro/clash/common/byteorder"
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

func (b Buffer) ReadUint8(r io.Reader) (uint8, error) {
	_, err := b.ReadFullFrom(r, 1)
	if err != nil {
		return 0, err
	}
	return b.buf.ReadByte()
}

func (b Buffer) ReadUint16(r io.Reader) (uint16, error) {
	_, err := b.ReadFullFrom(r, 2)
	if err != nil {
		return 0, err
	}
	return byteorder.Native.Uint16(b.buf.Next(2)), nil
}

func (b Buffer) ReadUint32(r io.Reader) (uint32, error) {
	_, err := b.ReadFullFrom(r, 4)
	if err != nil {
		return 0, err
	}
	return byteorder.Native.Uint32(b.buf.Next(4)), nil
}

func (b Buffer) ReadUint64(r io.Reader) (uint64, error) {
	_, err := b.ReadFullFrom(r, 8)
	if err != nil {
		return 0, err
	}
	return byteorder.Native.Uint64(b.buf.Next(8)), nil
}

func (b Buffer) ReadUint16be(r io.Reader) (uint16, error) {
	_, err := b.ReadFullFrom(r, 2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b.buf.Next(2)), nil
}

func (b Buffer) ReadUint32be(r io.Reader) (uint32, error) {
	_, err := b.ReadFullFrom(r, 4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b.buf.Next(4)), nil
}

func (b Buffer) ReadUint64be(r io.Reader) (uint64, error) {
	_, err := b.ReadFullFrom(r, 8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b.buf.Next(8)), nil
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

var bufferWriterPool = sync.Pool{New: func() any { return &BufferWriter{} }}

func GetBufferWriter() *BufferWriter {
	return bufferWriterPool.Get().(*BufferWriter)
}

func PutBufferWriter(buf *BufferWriter) {
	buf.Reset()
	bufferWriterPool.Put(buf)
}

const (
	smallBufferSize = 64
	maxInt          = int(^uint(0) >> 1)
)

type BufferReader []byte

type BufferWriter []byte

func (br *BufferReader) Len() int {
	return len(*br)
}

func (br *BufferReader) Cap() int {
	return cap(*br)
}

func (br *BufferReader) IsEmpty() bool {
	return br.Len() == 0
}

func (br *BufferReader) SplitAt(n int) (BufferReader, BufferReader) {
	if n > br.Len() {
		n = br.Len()
	}
	buf := *br
	return buf[:n], buf[n:]
}

func (br *BufferReader) SplitBy(f func(byte) bool) (BufferReader, BufferReader) {
	for i, c := range *br {
		if f(c) {
			return br.SplitAt(i)
		}
	}
	return *br, nil
}

func (br *BufferReader) ReadUint8() uint8 {
	r := (*br)[0]
	*br = (*br)[1:]
	return r
}

func (br *BufferReader) ReadUint16() uint16 {
	r := byteorder.Native.Uint16((*br)[:2])
	*br = (*br)[2:]
	return r
}

func (br *BufferReader) ReadUint32() uint32 {
	r := byteorder.Native.Uint32((*br)[:4])
	*br = (*br)[4:]
	return r
}

func (br *BufferReader) ReadUint64() uint64 {
	r := byteorder.Native.Uint64((*br)[:8])
	*br = (*br)[8:]
	return r
}

func (br *BufferReader) ReadUint16be() uint16 {
	r := binary.BigEndian.Uint16((*br)[:2])
	*br = (*br)[2:]
	return r
}

func (br *BufferReader) ReadUint32be() uint32 {
	r := binary.BigEndian.Uint32((*br)[:4])
	*br = (*br)[4:]
	return r
}

func (br *BufferReader) ReadUint64be() uint64 {
	r := binary.BigEndian.Uint64((*br)[:8])
	*br = (*br)[8:]
	return r
}

func (br *BufferReader) ReadUvarint() (uint64, error) {
	return binary.ReadUvarint(br)
}

func (br *BufferReader) ReadVarint() (int64, error) {
	return binary.ReadVarint(br)
}

func (br *BufferReader) Skip(n int) {
	*br = (*br)[n:]
}

func (br *BufferReader) Read(p []byte) (n int, err error) {
	n = copy(p, *br)
	*br = (*br)[n:]
	return
}

func (br *BufferReader) ReadByte() (byte, error) {
	if br.Len() == 0 {
		return 0, io.EOF
	}
	return br.ReadUint8(), nil
}

func (br *BufferReader) ReadIPv4() netip.Addr {
	ip := netip.AddrFrom4([4]byte((*br)[:4]))
	*br = (*br)[4:]
	return ip
}

func (br *BufferReader) ReadIPv6() netip.Addr {
	ip := netip.AddrFrom16([16]byte((*br)[:16]))
	*br = (*br)[16:]
	return ip
}

func (bw *BufferWriter) Len() int {
	return len(*bw)
}

func (bw *BufferWriter) Cap() int {
	return cap(*bw)
}

// tryGrowByReslice is an inlineable version of grow for the fast-case where the
// internal buffer only needs to be resliced.
// It returns the index where bytes should be written and whether it succeeded.
func (bw *BufferWriter) tryGrowByReslice(n int) (int, bool) {
	if l := len(*bw); n <= cap(*bw)-l {
		*bw = (*bw)[:l+n]
		return l, true
	}
	return 0, false
}

// growSlice grows b by n, preserving the original content of b.
// If the allocation fails, it panics with ErrTooLarge.
func growSlice(b []byte, n int) []byte {
	defer func() {
		if recover() != nil {
			panic(bytes.ErrTooLarge)
		}
	}()
	// TODO(http://golang.org/issue/51462): We should rely on the append-make
	// pattern so that the compiler can call runtime.growslice. For example:
	//	return append(b, make([]byte, n)...)
	// This avoids unnecessary zero-ing of the first len(b) bytes of the
	// allocated slice, but this pattern causes b to escape onto the heap.
	//
	// Instead use the append-make pattern with a nil slice to ensure that
	// we allocate buffers rounded up to the closest size class.
	c := len(b) + n // ensure enough space for n elements
	if c < 2*cap(b) {
		// The growth rate has historically always been 2x. In the future,
		// we could rely purely on append to determine the growth rate.
		c = 2 * cap(b)
	}
	b2 := append([]byte(nil), make([]byte, c)...)
	copy(b2, b)
	return b2[:len(b)]
}

// grow the buffer to guarantee space for n more bytes.
// It returns the index where bytes should be written.
// If the buffer can't grow it will panic with ErrTooLarge.
func (bw *BufferWriter) grow(n int) int {
	m := bw.Len()
	// Try to grow by means of a reslice.
	if i, ok := bw.tryGrowByReslice(n); ok {
		return i
	}
	if *bw == nil && n <= smallBufferSize {
		*bw = make([]byte, n, smallBufferSize)
		return 0
	}
	c := cap(*bw)
	if c > maxInt-c-n {
		panic(bytes.ErrTooLarge)
	} else if n > c/2-m {
		// Add b.off to account for *b[:b.off] being sliced off the front.
		*bw = growSlice((*bw)[:], n)
	}
	// Restore b.off and len(b.buf).
	*bw = (*bw)[:m+n]
	return m
}

func (bw *BufferWriter) Grow(n int) int {
	m, ok := bw.tryGrowByReslice(n)
	if !ok {
		m = bw.grow(n)
	}
	return m
}

func (bw *BufferWriter) next(n int) []byte {
	m := bw.Grow(n)
	return (*bw)[m : m+n]
}

func (bw *BufferWriter) PutUint8(v uint8) {
	m := bw.Grow(1)
	(*bw)[m] = v
}

func (bw *BufferWriter) PutUint16(v uint16) {
	byteorder.Native.PutUint16(bw.next(2), v)
}

func (bw *BufferWriter) PutUint32(v uint32) {
	byteorder.Native.PutUint32(bw.next(4), v)
}

func (bw *BufferWriter) PutUint64(v uint64) {
	byteorder.Native.PutUint64(bw.next(8), v)
}

func (bw *BufferWriter) PutUint16be(v uint16) {
	binary.BigEndian.PutUint16(bw.next(2), v)
}

func (bw *BufferWriter) PutUint32be(v uint32) {
	binary.BigEndian.PutUint32(bw.next(4), v)
}

func (bw *BufferWriter) PutUint64be(v uint64) {
	binary.BigEndian.PutUint64(bw.next(8), v)
}

func (bw *BufferWriter) PutUvarint(v uint64) {
	n := binary.MaxVarintLen64
	m := bw.Grow(n)

	n = binary.PutUvarint((*bw)[m:], v)
	*bw = (*bw)[:m+n]
}

func (bw *BufferWriter) PutVarint(v int64) {
	n := binary.MaxVarintLen64
	m := bw.Grow(n)

	n = binary.PutVarint((*bw)[m:], v)
	*bw = (*bw)[:m+n]
}

func (bw *BufferWriter) PutSlice(p []byte) {
	copy(bw.next(len(p)), p)
}

func (bw *BufferWriter) PutString(s string) {
	copy(bw.next(len(s)), s)
}

func (bw *BufferWriter) PutRune(r rune) {
	// Compare as uint32 to correctly handle negative runes.
	if uint32(r) < utf8.RuneSelf {
		bw.PutUint8(byte(r))
		return
	}
	m := bw.Grow(utf8.UTFMax)
	*bw = utf8.AppendRune((*bw)[:m], r)
}

func (bw *BufferWriter) ReadFull(r io.Reader, n int) error {
	l := bw.Len()
	_, err := io.ReadFull(r, bw.next(n))
	if err != nil {
		*bw = (*bw)[:l]
	}
	return err
}

func (bw *BufferWriter) WriteTo(w io.Writer) (n int64, err error) {
	if nBytes := bw.Len(); nBytes > 0 {
		m, e := w.Write((*bw)[:])
		if m > nBytes {
			panic("bytes.Buffer.WriteTo: invalid Write count")
		}
		n = int64(m)
		if e != nil {
			return n, e
		}
		// all bytes should have been written, by definition of
		// Write method in io.Writer
		if m != nBytes {
			return n, io.ErrShortWrite
		}
	}
	// Buffer is now empty; reset.
	bw.Reset()
	return n, nil
}

func (bw *BufferWriter) Slice(begin, end int) BufferWriter {
	w := (*bw)[begin:end]
	w.Reset()
	return w
}

func (bw *BufferWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	bw.PutSlice(p)
	return
}

func (bw *BufferWriter) Bytes() []byte {
	return (*bw)[:]
}

func (bw *BufferWriter) String() string {
	return string((*bw)[:])
}

func (bw *BufferWriter) Reset() {
	*bw = (*bw)[:0]
}
