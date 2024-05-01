package tls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
)

const sniffTimeout = 5 * time.Millisecond

func SniffHTTP(b []byte) string {
	if req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b))); err == nil {
		hostname := req.Host
		if host, _, err := net.SplitHostPort(req.Host); err == nil {
			hostname = host
		}
		if hostname != "" && hostname[len(hostname)-1] == '.' {
			hostname = hostname[:len(hostname)-1]
		}
		return hostname
	}
	return ""
}

func SniffTLS(b []byte) string {
	if len(b) < 47 || b[0] != 0x16 {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), sniffTimeout)
	defer cancel()

	serverName := ""
	tlsConfig := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName = info.ServerName
			cancel()
			return nil, nil
		},
	}

	conn := newFakeConn(bytes.NewReader(b))
	_ = tls.Server(conn, tlsConfig).HandshakeContext(ctx)

	if serverName != "" && serverName[len(serverName)-1] == '.' {
		serverName = serverName[:len(serverName)-1]
	}
	return serverName
}

func SniffQUIC(b []byte) string {
	if len(b) < 1200 {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), sniffTimeout)
	defer cancel()

	serverName := ""
	tlsConfig := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName = info.ServerName
			cancel()
			return nil, nil
		},
	}

	conn := newFakePacketConn(bytes.NewReader(b), ctx)
	l, err := quic.Listen(conn, tlsConfig, nil)
	if err == nil {
		_, _ = l.Accept(ctx)
		_ = l.Close()
	}
	return serverName
}

var _ net.Conn = (*fakeConn)(nil)

type fakeConn struct {
	r io.Reader
}

func (f *fakeConn) Read(b []byte) (n int, err error) {
	return f.r.Read(b)
}

func (f *fakeConn) Write(_ []byte) (n int, err error) {
	return 0, net.ErrClosed
}

func (f *fakeConn) Close() error                       { return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return nil }
func (f *fakeConn) RemoteAddr() net.Addr               { return nil }
func (f *fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }

func newFakeConn(r io.Reader) *fakeConn {
	return &fakeConn{
		r: r,
	}
}

var _ net.PacketConn = (*fakePacketConn)(nil)

var localAddr = &net.TCPAddr{Port: 12345}

type fakePacketConn struct {
	r   io.Reader
	ctx context.Context
}

func (pc *fakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	done := make(chan struct{})
	go func() {
		n, err = pc.r.Read(p)
		if n > 0 {
			close(done)
		}
	}()
	select {
	case <-done:
	case <-pc.ctx.Done():
		err = pc.ctx.Err()
	}
	return
}

func (pc *fakePacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	n = len(p)
	return
}

func (pc *fakePacketConn) Close() error                       { return nil }
func (pc *fakePacketConn) LocalAddr() net.Addr                { return localAddr }
func (pc *fakePacketConn) SetDeadline(_ time.Time) error      { return nil }
func (pc *fakePacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (pc *fakePacketConn) SetWriteDeadline(_ time.Time) error { return nil }
func (pc *fakePacketConn) SetReadBuffer(_ int) error          { return nil }
func (pc *fakePacketConn) SetWriteBuffer(_ int) error         { return nil }

func newFakePacketConn(r io.Reader, ctx context.Context) *fakePacketConn {
	return &fakePacketConn{
		r:   r,
		ctx: ctx,
	}
}

// VerifyHostnameInSNI reports whether s is a valid hostname.
//
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See RFC 6066, Section 3.
func VerifyHostnameInSNI(s string) bool {
	l := len(s)
	if l < 4 {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	d := -1
	for i := l - 1; i >= 0; i-- {
		c := s[i]
		if !isHostnameChar(c) {
			return false
		}
		if c == '.' {
			if i > 0 && s[i-1] == '.' {
				d = -1
				break
			}
			if d == -1 {
				d = i
			}
		}
	}
	if s[0] != '.' && 0 < d && d < l-2 {
		return true
	}
	return false
}

func isHostnameChar(c byte) bool {
	if c > 0x7a {
		return false
	}
	return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '-' || 'A' <= c && c <= 'Z'
}

func ToLowerASCII(s string) string {
	hasUpper := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			hasUpper = true
			break
		}
	}
	if !hasUpper {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
