package shadowaead

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
)

const (
	// payloadSizeMask is the maximum size of payload in bytes.
	payloadSizeMask = 0x3FFF    // 16*1024 - 1
	bufSize         = 17 * 1024 // >= 2+aead.Overhead()+payloadSizeMask+aead.Overhead()
)

var ErrZeroChunk = errors.New("zero chunk")

type Writer struct {
	io.Writer
	cipher.AEAD
	nonce [32]byte // should be sufficient for most nonce sizes
}

// NewWriter wraps an io.Writer with authenticated encryption.
func NewWriter(w io.Writer, aead cipher.AEAD) *Writer { return &Writer{Writer: w, AEAD: aead} }

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, bufSize)
		return &b
	},
}

// Write encrypts p and writes to the embedded io.Writer.
func (w *Writer) Write(p []byte) (n int, err error) {
	bufP := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufP)
	nonce := w.nonce[:w.NonceSize()]
	tag := w.Overhead()
	off := 2 + tag

	// compatible with snell
	if len(p) == 0 {
		(*bufP)[0], (*bufP)[1] = byte(0), byte(0)
		w.Seal((*bufP)[:0], nonce, (*bufP)[:2], nil)
		increment(nonce)
		_, err = w.Writer.Write((*bufP)[:off])
		return
	}

	for nr := 0; n < len(p) && err == nil; n += nr {
		nr = payloadSizeMask
		if n+nr > len(p) {
			nr = len(p) - n
		}
		(*bufP)[0], (*bufP)[1] = byte(nr>>8), byte(nr) // big-endian payload size
		w.Seal((*bufP)[:0], nonce, (*bufP)[:2], nil)
		increment(nonce)
		w.Seal((*bufP)[:off], nonce, p[n:n+nr], nil)
		increment(nonce)
		_, err = w.Writer.Write((*bufP)[:off+nr+tag])
	}
	return
}

// ReadFrom reads from the given io.Reader until EOF or error, encrypts and
// writes to the embedded io.Writer. Returns number of bytes read from r and
// any error encountered.
func (w *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	bufP := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufP)
	nonce := w.nonce[:w.NonceSize()]
	tag := w.Overhead()
	off := 2 + tag
	for {
		nr, er := r.Read((*bufP)[off : off+payloadSizeMask])
		n += int64(nr)
		(*bufP)[0], (*bufP)[1] = byte(nr>>8), byte(nr)
		w.Seal((*bufP)[:0], nonce, (*bufP)[:2], nil)
		increment(nonce)
		w.Seal((*bufP)[:off], nonce, (*bufP)[off:off+nr], nil)
		increment(nonce)
		if _, ew := w.Writer.Write((*bufP)[:off+nr+tag]); ew != nil {
			err = ew
			return
		}
		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			return
		}
	}
}

type Reader struct {
	io.Reader
	cipher.AEAD
	nonce [32]byte // should be sufficient for most nonce sizes
	bufP  *[]byte  // to be put back into bufPool
	off   int      // offset to unconsumed part of buf
}

// NewReader wraps an io.Reader with authenticated decryption.
func NewReader(r io.Reader, aead cipher.AEAD) *Reader { return &Reader{Reader: r, AEAD: aead} }

// Read and decrypt a record into p. len(p) >= max payload size + AEAD overhead.
func (r *Reader) read(p []byte) (int, error) {
	nonce := r.nonce[:r.NonceSize()]
	tag := r.Overhead()

	// decrypt payload size
	p = p[:2+tag]
	if _, err := io.ReadFull(r.Reader, p); err != nil {
		return 0, err
	}
	_, err := r.Open(p[:0], nonce, p, nil)
	increment(nonce)
	if err != nil {
		return 0, err
	}

	// decrypt payload
	size := (int(p[0])<<8 + int(p[1])) & payloadSizeMask
	if size == 0 {
		return 0, ErrZeroChunk
	}

	p = p[:size+tag]
	if _, err := io.ReadFull(r.Reader, p); err != nil {
		return 0, err
	}
	_, err = r.Open(p[:0], nonce, p, nil)
	increment(nonce)
	if err != nil {
		return 0, err
	}
	return size, nil
}

// Read reads from the embedded io.Reader, decrypts and writes to p.
func (r *Reader) Read(p []byte) (int, error) {
	if r.bufP == nil {
		if len(p) >= payloadSizeMask+r.Overhead() {
			return r.read(p)
		}
		bp := bufPool.Get().(*[]byte)
		n, err := r.read(*bp)
		if err != nil {
			return 0, err
		}
		*bp = (*bp)[:n]
		r.bufP = bp
		r.off = 0
	}

	n := copy(p, (*r.bufP)[r.off:])
	r.off += n
	if r.off == len(*r.bufP) {
		*r.bufP = (*r.bufP)[:bufSize]
		bufPool.Put(r.bufP)
		r.bufP = nil
	}
	return n, nil
}

// WriteTo reads from the embedded io.Reader, decrypts and writes to w until
// there's no more data to write or when an error occurs. Return number of
// bytes written to w and any error encountered.
func (r *Reader) WriteTo(w io.Writer) (n int64, err error) {
	if r.bufP == nil {
		r.bufP = bufPool.Get().(*[]byte)
		r.off = len(*r.bufP)
	}

	for {
		for r.off < len(*r.bufP) {
			nw, ew := w.Write((*r.bufP)[r.off:])
			r.off += nw
			n += int64(nw)
			if ew != nil {
				if r.off == len(*r.bufP) {
					*r.bufP = (*r.bufP)[:bufSize]
					bufPool.Put(r.bufP)
					r.bufP = nil
				}
				err = ew
				return
			}
		}

		nr, er := r.read(*r.bufP)
		if er != nil {
			if er != io.EOF {
				err = er
			}
			return
		}
		*r.bufP = (*r.bufP)[:nr]
		r.off = 0
	}
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

type Conn struct {
	net.Conn
	Cipher
	r *Reader
	w *Writer
}

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c net.Conn, ciph Cipher) *Conn { return &Conn{Conn: c, Cipher: ciph} }

func (c *Conn) initReader() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}

	aead, err := c.Decrypter(salt)
	if err != nil {
		return err
	}

	c.r = NewReader(c.Conn, aead)
	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

func (c *Conn) initWriter() error {
	salt := make([]byte, c.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := c.Encrypter(salt)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(salt)
	if err != nil {
		return err
	}
	c.w = NewWriter(c.Conn, aead)
	return nil
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}
