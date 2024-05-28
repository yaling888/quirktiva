package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/net/http2"

	"github.com/yaling888/quirktiva/common/convert"
	"github.com/yaling888/quirktiva/component/dialer"
	"github.com/yaling888/quirktiva/component/resolver"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/crypto"
	"github.com/yaling888/quirktiva/transport/gun"
	"github.com/yaling888/quirktiva/transport/h1"
	"github.com/yaling888/quirktiva/transport/h2"
	"github.com/yaling888/quirktiva/transport/header"
	"github.com/yaling888/quirktiva/transport/quic"
	"github.com/yaling888/quirktiva/transport/socks5"
	tls2 "github.com/yaling888/quirktiva/transport/tls"
	"github.com/yaling888/quirktiva/transport/vmess"
)

var _ C.ProxyAdapter = (*Vmess)(nil)

type Vmess struct {
	*Base
	client *vmess.Client
	option *VmessOption

	// for gun mux
	gunTLSConfig *tls.Config
	gunConfig    *gun.Config
	transport    *http2.Transport

	quicAEAD *crypto.AEAD
}

type VmessOption struct {
	BasicOption
	Name             string       `proxy:"name"`
	Server           string       `proxy:"server"`
	Port             int          `proxy:"port"`
	UUID             string       `proxy:"uuid"`
	AlterID          int          `proxy:"alterId"`
	Cipher           string       `proxy:"cipher"`
	UDP              bool         `proxy:"udp,omitempty"`
	Network          string       `proxy:"network,omitempty"`
	TLS              bool         `proxy:"tls,omitempty"`
	SkipCertVerify   bool         `proxy:"skip-cert-verify,omitempty"`
	ALPN             []string     `proxy:"alpn,omitempty"`
	ServerName       string       `proxy:"servername,omitempty"`
	HTTPOpts         HTTPOptions  `proxy:"http-opts,omitempty"`
	HTTP2Opts        HTTP2Options `proxy:"h2-opts,omitempty"`
	GrpcOpts         GrpcOptions  `proxy:"grpc-opts,omitempty"`
	WSOpts           WSOptions    `proxy:"ws-opts,omitempty"`
	QUICOpts         QUICOptions  `proxy:"quic-opts,omitempty"`
	RandomHost       bool         `proxy:"rand-host,omitempty"`
	RemoteDnsResolve bool         `proxy:"remote-dns-resolve,omitempty"`
}

type HTTPOptions struct {
	Method  string              `proxy:"method,omitempty"`
	Path    []string            `proxy:"path,omitempty"`
	Headers map[string][]string `proxy:"headers,omitempty"`
}

type HTTP2Options struct {
	Host    []string          `proxy:"host,omitempty"`
	Path    string            `proxy:"path,omitempty"`
	Headers map[string]string `proxy:"headers,omitempty"`
}

type GrpcOptions struct {
	GrpcServiceName string `proxy:"grpc-service-name,omitempty"`
}

type WSOptions struct {
	Path                string            `proxy:"path,omitempty"`
	Headers             map[string]string `proxy:"headers,omitempty"`
	MaxEarlyData        int               `proxy:"max-early-data,omitempty"`
	EarlyDataHeaderName string            `proxy:"early-data-header-name,omitempty"`
}

type QUICOptions struct {
	Security string `proxy:"cipher,omitempty"`
	Key      string `proxy:"key,omitempty"`
	Header   string `proxy:"obfs,omitempty"`
}

// StreamConn implements C.ProxyAdapter
func (v *Vmess) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	switch v.option.Network {
	case "ws":
		host, port, _ := net.SplitHostPort(v.addr)
		wsOpts := &vmess.WebsocketConfig{
			Host:                host,
			Port:                port,
			Headers:             http.Header{},
			Path:                v.option.WSOpts.Path,
			MaxEarlyData:        v.option.WSOpts.MaxEarlyData,
			EarlyDataHeaderName: v.option.WSOpts.EarlyDataHeaderName,
		}

		if len(v.option.WSOpts.Headers) != 0 {
			for key, value := range v.option.WSOpts.Headers {
				wsOpts.Headers.Add(key, value)
			}
		}

		if v.option.TLS {
			wsOpts.TLS = true
			wsOpts.TLSConfig = &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: v.option.SkipCertVerify,
				NextProtos:         []string{"http/1.1"},
			}
			if v.option.ServerName != "" {
				wsOpts.TLSConfig.ServerName = v.option.ServerName
				wsOpts.Host = v.option.ServerName
			} else if host1 := wsOpts.Headers.Get("Host"); host1 != "" {
				wsOpts.TLSConfig.ServerName = host1
				wsOpts.Host = host1
			}
		} else if v.option.RandomHost || wsOpts.Headers.Get("Host") == "" {
			wsOpts.Headers.Set("Host", convert.RandHost())
		}

		if wsOpts.Headers.Get("User-Agent") == "" {
			wsOpts.Headers.Set("User-Agent", convert.RandUserAgent())
		}
		c, err = vmess.StreamWebsocketConn(c, wsOpts)
	case "http":
		host := v.option.Server
		// readability first, so just copy default TLS logic
		if v.option.TLS {
			tlsOpts := &tls2.Config{
				Host:           host,
				SkipCertVerify: v.option.SkipCertVerify,
			}

			if v.option.ServerName != "" {
				tlsOpts.Host = v.option.ServerName
			}

			c, err = tls2.StreamTLSConn(c, tlsOpts)
			if err != nil {
				return nil, err
			}
		}

		httpOpts := &h1.HTTPConfig{
			Host:    host,
			Method:  v.option.HTTPOpts.Method,
			Path:    v.option.HTTPOpts.Path,
			Headers: make(map[string][]string),
		}

		if len(v.option.HTTPOpts.Headers) != 0 {
			for key, value := range v.option.HTTPOpts.Headers {
				httpOpts.Headers[key] = value
			}
		}

		if !v.option.TLS && (v.option.RandomHost || len(v.option.HTTPOpts.Headers["Host"]) == 0) {
			httpOpts.Headers["Host"] = []string{convert.RandHost()}
		}

		if len(v.option.HTTPOpts.Headers["User-Agent"]) == 0 {
			httpOpts.Headers["User-Agent"] = []string{convert.RandUserAgent()}
		}
		c = h1.StreamHTTPConn(c, httpOpts)
	case "h2":
		tlsOpts := tls2.Config{
			Host:           v.option.Server,
			SkipCertVerify: v.option.SkipCertVerify,
			NextProtos:     []string{"h2"},
		}

		if v.option.ServerName != "" {
			tlsOpts.Host = v.option.ServerName
		}

		c, err = tls2.StreamTLSConn(c, &tlsOpts)
		if err != nil {
			return nil, err
		}

		h2Opts := &h2.Config{
			Hosts:   v.option.HTTP2Opts.Host,
			Path:    v.option.HTTP2Opts.Path,
			Headers: http.Header{},
		}

		if len(v.option.HTTP2Opts.Headers) != 0 {
			for key, value := range v.option.HTTP2Opts.Headers {
				h2Opts.Headers.Add(key, value)
			}
		}

		if h2Opts.Headers.Get("User-Agent") == "" {
			h2Opts.Headers.Set("User-Agent", convert.RandUserAgent())
		}

		c, err = h2.StreamH2Conn(c, h2Opts)
	case "grpc":
		c, err = gun.StreamGunWithConn(c, v.gunTLSConfig, v.gunConfig)
	case "quic":
		quicOpts := &quic.Config{
			Host:           v.option.Server,
			Port:           v.option.Port,
			ALPN:           v.option.ALPN,
			ServerName:     v.option.Server,
			SkipCertVerify: v.option.SkipCertVerify,
			Header:         v.option.QUICOpts.Header,
			AEAD:           v.quicAEAD,
		}

		if v.option.ServerName != "" {
			quicOpts.ServerName = v.option.ServerName
		}

		c, err = quic.StreamQUICConn(c, quicOpts)
	default:
		// handle TLS
		if v.option.TLS {
			host, _, _ := net.SplitHostPort(v.addr)
			tlsOpts := &tls2.Config{
				Host:           host,
				SkipCertVerify: v.option.SkipCertVerify,
			}

			if v.option.ServerName != "" {
				tlsOpts.Host = v.option.ServerName
			}

			c, err = tls2.StreamTLSConn(c, tlsOpts)
		}
	}

	if err != nil {
		return nil, err
	}

	return v.client.StreamConn(c, parseVmessAddr(metadata))
}

// StreamPacketConn implements C.ProxyAdapter
func (v *Vmess) StreamPacketConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	// vmess use stream-oriented udp with a special address, so we need a net.UDPAddr
	if !metadata.Resolved() {
		rAddrs, err := resolver.LookupIP(context.Background(), metadata.Host)
		if err != nil {
			return c, fmt.Errorf("can't resolve ip, %w", err)
		}
		metadata.DstIP = rAddrs[0]
	}

	var err error
	c, err = v.StreamConn(c, metadata)
	if err != nil {
		return c, fmt.Errorf("new vmess client error: %w", err)
	}

	return WrapConn(&vmessPacketConn{Conn: c, rAddr: metadata.UDPAddr()}), nil
}

// DialContext implements C.ProxyAdapter
func (v *Vmess) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		c, err := gun.StreamGunWithTransport(v.transport, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func(cc net.Conn, e error) {
			safeConnClose(cc, e)
		}(c, err)

		c, err = v.client.StreamConn(c, parseVmessAddr(metadata))
		if err != nil {
			return nil, err
		}

		return NewConn(c, v), nil
	}

	c, err := v.dialContext(ctx, opts...)
	if err != nil {
		return nil, err
	}
	tcpKeepAlive(c)
	defer func(cc net.Conn, e error) {
		safeConnClose(cc, e)
	}(c, err)

	c, err = v.StreamConn(c, metadata)
	return NewConn(c, v), err
}

// ListenPacketContext implements C.ProxyAdapter
func (v *Vmess) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	var c net.Conn
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		// vmess use stream-oriented udp with a special address, so we need a net.UDPAddr
		if !metadata.Resolved() {
			rAddrs, err := resolver.LookupIP(context.Background(), metadata.Host)
			if err != nil {
				return nil, fmt.Errorf("can't resolve ip, %w", err)
			}
			metadata.DstIP = rAddrs[0]
		}

		c, err = gun.StreamGunWithTransport(v.transport, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func(cc net.Conn, e error) {
			safeConnClose(cc, e)
		}(c, err)

		c, err = v.client.StreamConn(c, parseVmessAddr(metadata))
		if err != nil {
			return nil, fmt.Errorf("new vmess client error: %w", err)
		}

		return NewPacketConn(&vmessPacketConn{Conn: c, rAddr: metadata.UDPAddr()}, v), nil
	}

	c, err = v.dialContext(ctx, opts...)
	if err != nil {
		return nil, err
	}

	tcpKeepAlive(c)
	defer func(cc net.Conn, e error) {
		safeConnClose(cc, e)
	}(c, err)

	c, err = v.StreamPacketConn(c, metadata)
	if err != nil {
		return nil, fmt.Errorf("new vmess client error: %w", err)
	}

	return NewPacketConn(c.(net.PacketConn), v), nil
}

func (v *Vmess) dialContext(ctx context.Context, opts ...dialer.Option) (net.Conn, error) {
	switch v.option.Network {
	case "quic":
		c, err := dialer.ListenPacket(ctx, "udp", "", v.Base.DialOptions(opts...)...)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", v.addr, err)
		}
		return c.(*net.UDPConn), nil
	}

	c, err := dialer.DialContext(ctx, "tcp", v.addr, v.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", v.addr, err)
	}
	return c, nil
}

func NewVmess(option VmessOption) (*Vmess, error) {
	security := strings.ToLower(option.Cipher)
	client, err := vmess.NewClient(vmess.Config{
		UUID:     option.UUID,
		AlterID:  uint16(option.AlterID),
		Security: security,
		HostName: option.Server,
		Port:     strconv.Itoa(option.Port),
		IsAead:   option.AlterID == 0,
	})
	if err != nil {
		return nil, err
	}

	switch option.Network {
	case "h2", "grpc", "quic":
		if !option.TLS {
			return nil, fmt.Errorf("TLS must be true with h2/grpc/quic network")
		}
	}

	v := &Vmess{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Vmess,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
			dns:   option.RemoteDnsResolve,
		},
		client: client,
		option: &option,
	}

	host := option.Server
	if option.ServerName != "" {
		host = option.ServerName
	}

	switch option.Network {
	case "h2":
		if len(option.HTTP2Opts.Host) == 0 {
			option.HTTP2Opts.Host = append(option.HTTP2Opts.Host, host)
		}
	case "grpc":
		dialFn := func(_, _ string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
			defer cancel()
			c, err := dialer.DialContext(ctx, "tcp", v.addr, v.Base.DialOptions()...)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %w", v.addr, err)
			}
			tcpKeepAlive(c)
			return c, nil
		}

		gunConfig := &gun.Config{
			ServiceName: v.option.GrpcOpts.GrpcServiceName,
			Host:        v.option.ServerName,
		}
		tlsConfig := &tls.Config{
			InsecureSkipVerify: v.option.SkipCertVerify,
			ServerName:         v.option.ServerName,
		}

		if v.option.ServerName == "" {
			host, _, _ := net.SplitHostPort(v.addr)
			tlsConfig.ServerName = host
			gunConfig.Host = host
		}

		v.gunTLSConfig = tlsConfig
		v.gunConfig = gunConfig
		v.transport = gun.NewHTTP2Client(dialFn, tlsConfig)
	case "quic":
		quicAEAD, err := crypto.NewAEAD(v.option.QUICOpts.Security, v.option.QUICOpts.Key, "v2ray-quic-salt")
		if err != nil {
			return nil, fmt.Errorf("invalid quic-opts: %w", err)
		}
		v.quicAEAD = quicAEAD
		_, err = header.New(v.option.QUICOpts.Header)
		if err != nil {
			return nil, fmt.Errorf("invalid quic-opts: %w", err)
		}
	}

	return v, nil
}

func parseVmessAddr(metadata *C.Metadata) *vmess.DstAddr {
	var addrType byte
	var addr []byte
	switch metadata.AddrType() {
	case socks5.AtypIPv4:
		addrType = vmess.AtypIPv4
		addr = make([]byte, net.IPv4len)
		copy(addr[:], metadata.DstIP.AsSlice())
	case socks5.AtypIPv6:
		addrType = vmess.AtypIPv6
		addr = make([]byte, net.IPv6len)
		copy(addr[:], metadata.DstIP.AsSlice())
	case socks5.AtypDomainName:
		addrType = vmess.AtypDomainName
		addr = make([]byte, len(metadata.Host)+1)
		addr[0] = byte(len(metadata.Host))
		copy(addr[1:], metadata.Host)
	}

	return &vmess.DstAddr{
		UDP:      metadata.NetWork == C.UDP,
		AddrType: addrType,
		Addr:     addr,
		Port:     uint(metadata.DstPort),
	}
}

type vmessPacketConn struct {
	net.Conn
	rAddr net.Addr
}

func (uc *vmessPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	realAddr := uc.rAddr.(*net.UDPAddr)
	destAddr := addr.(*net.UDPAddr)
	if !realAddr.IP.Equal(destAddr.IP) || realAddr.Port != destAddr.Port {
		return 0, errors.New("udp packet dropped due to mismatched remote address")
	}
	return uc.Conn.Write(b)
}

func (uc *vmessPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := uc.Conn.Read(b)
	return n, uc.rAddr, err
}
