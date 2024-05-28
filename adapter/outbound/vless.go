package outbound

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"

	"golang.org/x/net/http2"

	"github.com/yaling888/quirktiva/common/convert"
	"github.com/yaling888/quirktiva/common/pool"
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
	"github.com/yaling888/quirktiva/transport/vless"
	"github.com/yaling888/quirktiva/transport/vmess"
)

const (
	// max packet length
	maxLength = 1024 << 4
)

var _ C.ProxyAdapter = (*Vless)(nil)

type Vless struct {
	*Base
	client *vless.Client
	option *VlessOption

	// for gun mux
	gunTLSConfig *tls.Config
	gunConfig    *gun.Config
	transport    *http2.Transport

	quicAEAD *crypto.AEAD
}

type VlessOption struct {
	BasicOption
	Name             string            `proxy:"name"`
	Server           string            `proxy:"server"`
	Port             int               `proxy:"port"`
	UUID             string            `proxy:"uuid"`
	UDP              bool              `proxy:"udp,omitempty"`
	Network          string            `proxy:"network,omitempty"`
	TLS              bool              `proxy:"tls,omitempty"`
	SkipCertVerify   bool              `proxy:"skip-cert-verify,omitempty"`
	ALPN             []string          `proxy:"alpn,omitempty"`
	ServerName       string            `proxy:"servername,omitempty"`
	HTTPOpts         HTTPOptions       `proxy:"http-opts,omitempty"`
	HTTP2Opts        HTTP2Options      `proxy:"h2-opts,omitempty"`
	GrpcOpts         GrpcOptions       `proxy:"grpc-opts,omitempty"`
	WSOpts           WSOptions         `proxy:"ws-opts,omitempty"`
	QUICOpts         QUICOptions       `proxy:"quic-opts,omitempty"`
	AEADOpts         crypto.AEADOption `proxy:"aead-opts,omitempty"`
	RandomHost       bool              `proxy:"rand-host,omitempty"`
	RemoteDnsResolve bool              `proxy:"remote-dns-resolve,omitempty"`
}

// StreamConn implements C.ProxyAdapter
func (v *Vless) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
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

	c, err = crypto.StreamAEADConnOrNot(c, v.option.AEADOpts)
	if err != nil {
		return nil, err
	}

	return v.client.StreamConn(c, parseVlessAddr(metadata))
}

// StreamPacketConn implements C.ProxyAdapter
func (v *Vless) StreamPacketConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	// vless use stream-oriented udp with a special address, so we need a net.UDPAddr
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
		return c, fmt.Errorf("new vless client error: %w", err)
	}

	return WrapConn(&vlessPacketConn{Conn: c, rAddr: metadata.UDPAddr()}), nil
}

// DialContext implements C.ProxyAdapter
func (v *Vless) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		c, err := gun.StreamGunWithTransport(v.transport, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func(cc net.Conn, e error) {
			safeConnClose(cc, e)
		}(c, err)

		c, err = v.client.StreamConn(c, parseVlessAddr(metadata))
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
func (v *Vless) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	var c net.Conn
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		// vless use stream-oriented udp with a special address, so we need a net.UDPAddr
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

		c, err = v.client.StreamConn(c, parseVlessAddr(metadata))
		if err != nil {
			return nil, fmt.Errorf("new vless client error: %w", err)
		}

		return NewPacketConn(&vlessPacketConn{Conn: c, rAddr: metadata.UDPAddr()}, v), nil
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
		return nil, fmt.Errorf("new vless client error: %w", err)
	}

	return NewPacketConn(c.(net.PacketConn), v), nil
}

func (v *Vless) dialContext(ctx context.Context, opts ...dialer.Option) (net.Conn, error) {
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

func parseVlessAddr(metadata *C.Metadata) *vless.DstAddr {
	var addrType byte
	var addr []byte
	switch metadata.AddrType() {
	case socks5.AtypIPv4:
		addrType = vless.AtypIPv4
		addr = make([]byte, net.IPv4len)
		copy(addr[:], metadata.DstIP.AsSlice())
	case socks5.AtypIPv6:
		addrType = vless.AtypIPv6
		addr = make([]byte, net.IPv6len)
		copy(addr[:], metadata.DstIP.AsSlice())
	case socks5.AtypDomainName:
		addrType = vless.AtypDomainName
		addr = make([]byte, len(metadata.Host)+1)
		addr[0] = byte(len(metadata.Host))
		copy(addr[1:], metadata.Host)
	}

	return &vless.DstAddr{
		UDP:      metadata.NetWork == C.UDP,
		AddrType: addrType,
		Addr:     addr,
		Port:     uint(metadata.DstPort),
	}
}

type vlessPacketConn struct {
	net.Conn
	rAddr  net.Addr
	remain int
	mux    sync.Mutex
}

func (vc *vlessPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	realAddr := vc.rAddr.(*net.UDPAddr)
	destAddr := addr.(*net.UDPAddr)
	if !realAddr.IP.Equal(destAddr.IP) || realAddr.Port != destAddr.Port {
		return 0, errors.New("udp packet dropped due to mismatched remote address")
	}

	total := len(b)
	if total == 0 {
		return 0, nil
	}
	if total <= maxLength {
		return writePacket(vc.Conn, b)
	}

	offset := 0
	for {
		cursor := min(offset+maxLength, total)

		n, err := writePacket(vc.Conn, b[offset:cursor])
		if err != nil {
			return offset + n, err
		}

		offset = cursor
		if offset == total {
			break
		}
	}

	return total, nil
}

func (vc *vlessPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	vc.mux.Lock()
	defer vc.mux.Unlock()

	if vc.remain > 0 {
		length := min(len(b), vc.remain)

		n, err := vc.Conn.Read(b[:length])
		if err != nil {
			return n, vc.rAddr, err
		}

		vc.remain -= n

		return n, vc.rAddr, nil
	}

	if n, err := io.ReadFull(vc.Conn, b[:2]); err != nil {
		return n, vc.rAddr, fmt.Errorf("read length error: %w", err)
	}

	total := int(binary.BigEndian.Uint16(b[:2]))
	if total == 0 || total > maxLength {
		return 0, vc.rAddr, fmt.Errorf("invalid packet length: %d", total)
	}

	length := min(len(b), total)

	if n, err := io.ReadFull(vc.Conn, b[:length]); err != nil {
		return n, vc.rAddr, fmt.Errorf("read packet error: %w", err)
	}

	vc.remain = total - length

	return length, vc.rAddr, nil
}

func writePacket(w io.Writer, b []byte) (n int, err error) {
	bufP := pool.GetNetBuf()
	defer pool.PutNetBuf(bufP)

	binary.BigEndian.PutUint16(*bufP, uint16(len(b)))
	n = copy((*bufP)[2:], b)
	_, err = w.Write((*bufP)[:2+n])
	return
}

func NewVless(option VlessOption) (*Vless, error) {
	if option.Network != "ws" && !option.TLS {
		return nil, errors.New("TLS must be true with tcp/http/h2/grpc/quic network")
	}

	if _, err := crypto.VerifyAEADOption(option.AEADOpts, true); err != nil {
		return nil, err
	}

	client, err := vless.NewClient(option.UUID)
	if err != nil {
		return nil, err
	}

	v := &Vless{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Vless,
			udp:   option.UDP,
			iface: option.Interface,
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
