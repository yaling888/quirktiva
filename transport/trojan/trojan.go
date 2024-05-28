package trojan

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/yaling888/quirktiva/common/pool"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/h2"
	"github.com/yaling888/quirktiva/transport/socks5"
	"github.com/yaling888/quirktiva/transport/vmess"
)

const (
	// max packet length
	maxLength = 8192
)

var (
	defaultALPN          = []string{"h2", "http/1.1"}
	defaultWebsocketALPN = []string{"http/1.1"}

	crlf = []byte{'\r', '\n'}
)

type Command = byte

const (
	CommandTCP byte = 1
	CommandUDP byte = 3
)

type Option struct {
	Password       string
	ALPN           []string
	ServerName     string
	SkipCertVerify bool
}

type HTTPOptions struct {
	Host    string
	Port    int
	Hosts   []string
	Path    string
	Headers http.Header
}

type WebsocketOption struct {
	Host    string
	Port    string
	Path    string
	Headers http.Header
}

type Trojan struct {
	option      *Option
	hexPassword []byte
}

func (t *Trojan) StreamConn(conn net.Conn) (net.Conn, error) {
	alpn := defaultALPN
	if len(t.option.ALPN) != 0 {
		alpn = t.option.ALPN
	}

	tlsConfig := &tls.Config{
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: t.option.SkipCertVerify,
		ServerName:         t.option.ServerName,
	}

	tlsConn := tls.Client(conn, tlsConfig)

	// fix tls handshake not timeout
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func (t *Trojan) StreamH2Conn(conn net.Conn, h2Option *HTTPOptions) (net.Conn, error) {
	tlsConfig := &tls.Config{
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: t.option.SkipCertVerify,
		ServerName:         t.option.ServerName,
	}

	tlsConn := tls.Client(conn, tlsConfig)

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	return h2.StreamH2Conn(tlsConn, &h2.Config{
		Hosts:   h2Option.Hosts,
		Path:    h2Option.Path,
		Headers: h2Option.Headers,
	})
}

func (t *Trojan) StreamWebsocketConn(conn net.Conn, wsOptions *WebsocketOption) (net.Conn, error) {
	alpn := defaultWebsocketALPN
	if len(t.option.ALPN) != 0 {
		alpn = t.option.ALPN
	}

	tlsConfig := &tls.Config{
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: t.option.SkipCertVerify,
		ServerName:         t.option.ServerName,
	}

	return vmess.StreamWebsocketConn(conn, &vmess.WebsocketConfig{
		Host:      wsOptions.Host,
		Port:      wsOptions.Port,
		Path:      wsOptions.Path,
		Headers:   wsOptions.Headers,
		TLS:       true,
		TLSConfig: tlsConfig,
	})
}

func (t *Trojan) WriteHeader(w io.Writer, command Command, socks5Addr []byte) error {
	buf := pool.BufferWriter{}

	buf.PutSlice(t.hexPassword)
	buf.PutSlice(crlf)

	buf.PutUint8(command)
	buf.PutSlice(socks5Addr)
	buf.PutSlice(crlf)

	_, err := w.Write(buf.Bytes())
	return err
}

func (t *Trojan) PacketConn(conn net.Conn) net.PacketConn {
	return &PacketConn{
		Conn: conn,
	}
}

func writePacket(w io.Writer, socks5Addr, payload []byte) (n int, err error) {
	bufP := pool.GetNetBuf()
	defer pool.PutNetBuf(bufP)

	n = len(payload)
	t := copy(*bufP, socks5Addr)
	binary.BigEndian.PutUint16((*bufP)[t:], uint16(n))
	t += 2
	t += copy((*bufP)[t:], crlf)
	t += copy((*bufP)[t:], payload)

	delta := t - n
	n, err = w.Write((*bufP)[:t])
	if n < t && err == nil {
		err = io.ErrShortWrite
	}
	n = max(n-delta, 0)
	return
}

func WritePacket(w io.Writer, socks5Addr, payload []byte) (n int, err error) {
	total := len(payload)
	if total <= maxLength {
		return writePacket(w, socks5Addr, payload)
	}

	offset := 0
	cursor := 0
	for {
		cursor = min(offset+maxLength, total)

		n, err = writePacket(w, socks5Addr, payload[offset:cursor])

		offset = min(offset+n, total)
		if err != nil || offset == total {
			n = offset
			return
		}
	}
}

func ReadPacket(r io.Reader, payload []byte) (addr *net.UDPAddr, n int, remain int, err error) {
	var socAddr socks5.Addr
	socAddr, err = socks5.ReadAddr(r, payload)
	if err != nil {
		if err != io.EOF {
			err = fmt.Errorf("read addr error, %w", err)
		}
		return
	}
	addr = socAddr.UDPAddr()
	if addr == nil {
		err = errors.New("parse addr error")
		return
	}

	if _, err = io.ReadFull(r, payload[:2]); err != nil {
		if err != io.EOF {
			err = fmt.Errorf("read length error, %w", err)
		}
		return
	}

	total := int(binary.BigEndian.Uint16(payload[:2]))
	if total > maxLength {
		err = errors.New("invalid packet")
		return
	}

	// read crlf
	if _, err = io.ReadFull(r, payload[:2]); err != nil {
		if err != io.EOF {
			err = fmt.Errorf("read crlf error, %w", err)
		}
		return
	}

	length := min(len(payload), total)
	if length, err = io.ReadFull(r, payload[:length]); err != nil && err != io.EOF {
		err = fmt.Errorf("read packet error, %w", err)
	}

	return addr, length, total - length, err
}

func New(option *Option) *Trojan {
	return &Trojan{option, hexSha224([]byte(option.Password))}
}

type PacketConn struct {
	net.Conn
	remain int
	rAddr  net.Addr
	mux    sync.Mutex
}

func (pc *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return WritePacket(pc, socks5.ParseAddr(addr.String()), b)
}

func (pc *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	pc.mux.Lock()
	defer pc.mux.Unlock()
	if pc.remain != 0 {
		length := min(len(b), pc.remain)

		n, err := pc.Conn.Read(b[:length])

		pc.remain -= n
		addr := pc.rAddr
		if pc.remain == 0 {
			pc.rAddr = nil
		}

		return n, addr, err
	}

	addr, n, remain, err := ReadPacket(pc.Conn, b)
	if err == nil && remain > 0 {
		pc.remain = remain
		pc.rAddr = addr
	}

	return n, addr, err
}

func hexSha224(data []byte) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	hash.Write(data)
	hex.Encode(buf, hash.Sum(nil))
	return buf
}
