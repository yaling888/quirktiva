package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/yaling888/quirktiva/common/pool"
)

type AEADOption struct {
	Cipher string `proxy:"cipher,omitempty"`
	Key    string `proxy:"key,omitempty"`
	Salt   string `proxy:"salt,omitempty"`
}

var _ net.Conn = (*aeadConn)(nil)

type aeadConn struct {
	net.Conn
	cipher *AEAD

	rMux sync.Mutex
	buf  []byte
	lasR int
}

func (c *aeadConn) Read(p []byte) (n int, err error) {
	c.rMux.Lock()
	defer c.rMux.Unlock()

	if c.lasR > 0 && c.buf != nil {
		n = copy(p, c.buf[len(c.buf)-c.lasR:])
		c.lasR -= n
		return
	}

	if c.buf == nil {
		c.buf = make([]byte, 64<<10)
	} else {
		c.buf = c.buf[:64<<10]
	}

	defer func() {
		if err != nil {
			c.lasR = 0
			c.buf = nil
		}
	}()

	hdSize := c.cipher.NonceSize() + 2
	_, err = io.ReadFull(c.Conn, c.buf[:hdSize])
	if err != nil {
		return
	}

	length := binary.BigEndian.Uint16(c.buf[c.cipher.NonceSize():])
	if length == 0 {
		err = io.EOF
		return
	}

	nonce := make([]byte, c.cipher.NonceSize())
	copy(nonce, c.buf[:c.cipher.NonceSize()])

	_, err = io.ReadAtLeast(c.Conn, c.buf[:length], int(length))
	if err != nil {
		return
	}

	b, err := c.cipher.Open(c.buf[:0], nonce, c.buf[:length], nil)
	if err != nil {
		return
	}

	c.lasR = len(b)
	c.buf = c.buf[:c.lasR]

	n = copy(p, c.buf[len(c.buf)-c.lasR:])
	c.lasR -= n
	return
}

func (c *aeadConn) Write(p []byte) (n int, err error) {
	bufP := pool.GetBufferWriter()
	defer pool.PutBufferWriter(bufP)

	bufP.Grow(c.cipher.NonceSize() + 2 + c.cipher.Overhead() + len(p))

	nonce := (*bufP)[:c.cipher.NonceSize()]
	if _, err = rand.Read(nonce); err != nil {
		return
	}

	b := c.cipher.Seal((*bufP)[:c.cipher.NonceSize()+2], nonce, p, nil)
	lenB := len(b)

	binary.BigEndian.PutUint16(b[c.cipher.NonceSize():], uint16(lenB-c.cipher.NonceSize()-2))

	lenP := len(p)
	delta := lenB - lenP
	nw, err := c.Conn.Write(b)
	n = max(nw-delta, 0)
	if n < lenP && err == nil {
		err = io.ErrShortWrite
	}
	return
}

func (c *aeadConn) Close() (err error) {
	err = c.Conn.Close()

	c.rMux.Lock()
	defer c.rMux.Unlock()

	c.lasR = 0
	c.buf = nil
	return
}

func StreamAEADConn(conn net.Conn, opt AEADOption) (net.Conn, error) {
	aead, err := NewAEAD(opt.Cipher, opt.Key, opt.Salt)
	if err != nil {
		return nil, err
	}

	if aead == nil {
		return nil, fmt.Errorf("unsupported cipher: %s", opt.Cipher)
	}

	return &aeadConn{
		Conn:   conn,
		cipher: aead,
	}, nil
}

func StreamAEADConnOrNot(conn net.Conn, opt AEADOption) (net.Conn, error) {
	if opt.Cipher == "" || strings.ToLower(opt.Cipher) == "none" {
		return conn, nil
	}

	return StreamAEADConn(conn, opt)
}

func VerifyAEADOption(opt AEADOption, allowNone bool) (bool, error) {
	if !allowNone && (opt.Cipher == "" || strings.ToLower(opt.Cipher) == "none" || opt.Key == "") {
		return false, nil
	}
	if _, err := NewAEAD(opt.Cipher, opt.Key, opt.Salt); err != nil {
		return false, err
	}
	return true, nil
}
