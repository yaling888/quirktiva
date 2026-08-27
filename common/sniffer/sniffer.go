package sniffer

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"time"
	"unsafe"

	"github.com/quic-go/quic-go"
)

const (
	OFF SniffingType = iota
	HTTP
	TLS
	QUIC
)

type SniffingType int

func (s SniffingType) String() string {
	switch s {
	case TLS:
		return "tls sni"
	case QUIC:
		return "quic sni"
	case HTTP:
		return "http hostname"
	case OFF:
		return "off"
	default:
		return "unknown"
	}
}

func SniffHTTP(conn net.Conn, timeout time.Duration) string {
	hostname := ""
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	if req, err := readRequest(bufio.NewReader(conn)); err == nil {
		hostname = cutHost(req.Host)
		if _, err = netip.ParseAddr(hostname); err == nil {
			hostname = cutHost(req.Header.Get("Host"))
		}
		hostname = trimLastDot(hostname)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return hostname
}

func SniffTLS(conn net.Conn, timeout time.Duration) (serverName string, attemptECH bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsConfig := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			cancel()
			if serverName == "" {
				serverName = trimLastDot(info.ServerName)
			}
			return nil, nil
		},
		GetEncryptedClientHelloKeys: func(info *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			cancel()
			serverName = trimLastDot(info.ServerName)
			attemptECH = true
			return nil, net.ErrClosed
		},
	}

	serverConn := tls.Server(conn, tlsConfig)
	_ = serverConn.HandshakeContext(ctx)
	_ = serverConn.Close()
	return serverName, attemptECH
}

var defaultQUICConfig = quic.Config{Versions: quic.SupportedVersions(), Allow0RTT: true}

func SniffQUIC(conn net.PacketConn, timeout time.Duration) (serverName string, attemptECH bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			cancel()
			serverName = info.ServerName
			return nil, nil
		},
		GetEncryptedClientHelloKeys: func(info *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			cancel()
			serverName = info.ServerName
			attemptECH = true
			return nil, net.ErrClosed
		},
	}

	l, err := quic.ListenEarly(conn, tlsConfig, &defaultQUICConfig)
	if err == nil {
		_, _ = l.Accept(ctx)
		_ = l.Close()
	}
	return serverName, attemptECH
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
	return unsafe.String(&b[0], len(b))
}

func isHostnameChar(c byte) bool {
	if c > 0x7a {
		return false
	}
	return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '-' || 'A' <= c && c <= 'Z'
}

func cutHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func trimLastDot(host string) string {
	if l := len(host); l > 0 && host[l-1] == '.' {
		host = host[:l-1]
	}
	return host
}

//go:linkname readRequest net/http.readRequest
func readRequest(_ *bufio.Reader) (req *http.Request, err error)
