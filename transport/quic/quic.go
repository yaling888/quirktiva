package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/yaling888/quirktiva/common/pool"
	"github.com/yaling888/quirktiva/component/resolver"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/crypto"
	"github.com/yaling888/quirktiva/transport/header"
)

var defaultALPN = []string{"h3", "h3-29", "h3-Q050", "h3-Q046", "h3-Q043", "hq-interop", "quic"}

type Config struct {
	Header         string
	AEAD           *crypto.AEAD
	Host           string
	Port           int
	ALPN           []string
	ServerName     string
	SkipCertVerify bool
}

var _ net.PacketConn = (*rawConn)(nil)

type rawConn struct {
	net.PacketConn
	header header.Header
	cipher *crypto.AEAD
}

func (rc *rawConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	obfs := rc.header
	cipher := rc.cipher
	if obfs == nil && cipher == nil {
		return rc.PacketConn.ReadFrom(p)
	}

	bufP := pool.GetBufferWriter()
	defer pool.PutBufferWriter(bufP)

	offset := 0
	if obfs != nil {
		offset = obfs.Size()
	}

	bufP.Grow(offset + len(p))
	if cipher != nil {
		bufP.Grow(cipher.NonceSize() + cipher.Overhead())
	}

	for {
		n, addr, err = rc.PacketConn.ReadFrom(*bufP)
		if n <= offset {
			if err != nil {
				return
			}
			continue
		}

		if cipher == nil {
			nr := n - offset
			n = copy(p, bufP.Bytes()[offset:n])
			if n < nr && err == nil {
				err = io.ErrShortBuffer
			}
			return
		}

		b, er := cipher.Decrypt(bufP.Bytes()[offset:n])
		if er != nil {
			if err != nil {
				return
			}
			continue
		}

		n = copy(p, b)
		if n < len(b) {
			err = io.ErrShortBuffer
		}
		return
	}
}

func (rc *rawConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	obfs := rc.header
	cipher := rc.cipher
	if obfs == nil && cipher == nil {
		return rc.PacketConn.WriteTo(p, addr)
	}

	bufP := pool.GetBufferWriter()
	defer pool.PutBufferWriter(bufP)

	if obfs != nil {
		bufP.Grow(obfs.Size())
		obfs.Fill(bufP.Bytes())
	}

	if cipher != nil {
		_, err = cipher.Encrypt(bufP, p)
		if err != nil {
			return
		}
	} else {
		bufP.PutSlice(p)
	}

	lenP := len(p)
	delta := bufP.Len() - lenP
	nw, err := rc.PacketConn.WriteTo(bufP.Bytes(), addr)
	n = max(nw-delta, 0)
	if n < lenP && err == nil {
		err = io.ErrShortWrite
	}
	return
}

func (rc *rawConn) Close() error {
	rc.header = nil
	rc.cipher = nil
	return rc.PacketConn.Close()
}

func (rc *rawConn) SyscallConn() (syscall.RawConn, error) {
	if c, ok := rc.PacketConn.(*net.UDPConn); ok {
		return c.SyscallConn()
	}
	return nil, syscall.EINVAL
}

var _ net.Conn = (*quicConn)(nil)

type quicConn struct {
	conn      quic.Connection
	stream    quic.Stream
	transport *quic.Transport
}

func (qc *quicConn) Read(b []byte) (n int, err error) {
	return qc.stream.Read(b)
}

func (qc *quicConn) Write(b []byte) (n int, err error) {
	return qc.stream.Write(b)
}

func (qc *quicConn) Close() error {
	_ = qc.stream.Close()
	_ = qc.conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")

	if err := qc.transport.Close(); err != nil {
		return err
	}
	if err := qc.transport.Conn.Close(); err != nil {
		return err
	}
	return nil
}

func (qc *quicConn) LocalAddr() net.Addr {
	return qc.conn.LocalAddr()
}

func (qc *quicConn) RemoteAddr() net.Addr {
	return qc.conn.RemoteAddr()
}

func (qc *quicConn) SetDeadline(t time.Time) error {
	return qc.stream.SetDeadline(t)
}

func (qc *quicConn) SetReadDeadline(t time.Time) error {
	return qc.stream.SetReadDeadline(t)
}

func (qc *quicConn) SetWriteDeadline(t time.Time) error {
	return qc.stream.SetWriteDeadline(t)
}

func StreamQUICConn(conn net.Conn, cfg *Config) (net.Conn, error) {
	pc, ok := conn.(net.PacketConn)
	if !ok {
		return nil, errors.New("conn is not a net.PacketConn")
	}

	hd, err := header.New(cfg.Header)
	if err != nil {
		return nil, err
	}

	ip, err := resolver.ResolveProxyServerHost(cfg.Host)
	if err != nil {
		return nil, err
	}

	alpn := defaultALPN
	if len(cfg.ALPN) != 0 {
		alpn = cfg.ALPN
	}

	serverName := cfg.Host
	if cfg.ServerName != "" {
		serverName = cfg.ServerName
	}

	tlsConfig := &tls.Config{
		NextProtos:         alpn,
		ServerName:         serverName,
		InsecureSkipVerify: cfg.SkipCertVerify,
		MinVersion:         tls.VersionTLS13,
	}

	quicConfig := &quic.Config{
		// Allow0RTT:               true,
		// EnableDatagrams:         true,
		// DisablePathMTUDiscovery: true,
		MaxIdleTimeout:       60 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
		HandshakeIdleTimeout: C.DefaultTLSTimeout,
	}

	var rConn net.PacketConn
	if cfg.AEAD == nil && hd == nil {
		rConn = pc
	} else {
		rConn = &rawConn{
			PacketConn: pc,
			header:     hd,
			cipher:     cfg.AEAD,
		}
	}

	transport := &quic.Transport{
		Conn:               rConn,
		ConnectionIDLength: 12,
	}

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
	defer cancel()

	qConn, err := transport.Dial(ctx, &net.UDPAddr{IP: ip.AsSlice(), Port: cfg.Port}, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic dial -> %s:%d error: %w", ip, cfg.Port, err)
	}

	stream, err := qConn.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("quic open stream -> %s:%d error: %w", ip, cfg.Port, err)
	}

	return &quicConn{
		conn:      qConn,
		stream:    stream,
		transport: transport,
	}, nil
}
