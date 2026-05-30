package outbound

import (
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

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
	tls2 "github.com/yaling888/quirktiva/transport/tls"
	"github.com/yaling888/quirktiva/transport/vmess"
)

//go:linkname tlsRegistry github.com/sagernet/sing-vmess/vless.tlsRegistry
var tlsRegistry []func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr)

func init() {
	tlsRegistry = append(tlsRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr) {
		uConn, loaded := N.CastReader[*utls.UConn](conn)
		if loaded {
			return true, uConn.NetConn(), reflect.TypeFor[utls.Conn](), uintptr(unsafe.Pointer(uConn.Conn))
		}
		tlsConn, loaded := N.CastReader[*utls.Conn](conn)
		if loaded {
			return true, tlsConn.NetConn(), reflect.TypeFor[utls.Conn](), uintptr(unsafe.Pointer(tlsConn))
		}
		return
	})
}

var _ C.ProxyAdapter = (*Vless)(nil)

type Vless struct {
	*Base
	client *vless.Client
	option *VlessOption

	// for gun mux
	gunTLSConfig *tls.Config
	gunConfig    *gun.Config
	transport    *http.Transport

	quicAEAD  *crypto.AEAD
	echConfig string
	lookupECH bool

	realityConfig *tls2.RealityConfig
}

type RealityOptions struct {
	PublicKey string `proxy:"public-key"`
	ShortID   string `proxy:"short-id"`
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
	ECHConfig        string            `proxy:"ech-config,omitempty"`
	ECH              bool              `proxy:"ech,omitempty"`
	HTTPOpts         HTTPOptions       `proxy:"http-opts,omitempty"`
	HTTP2Opts        HTTP2Options      `proxy:"h2-opts,omitempty"`
	GrpcOpts         GrpcOptions       `proxy:"grpc-opts,omitempty"`
	WSOpts           WSOptions         `proxy:"ws-opts,omitempty"`
	QUICOpts         QUICOptions       `proxy:"quic-opts,omitempty"`
	AEADOpts         crypto.AEADOption `proxy:"aead-opts,omitempty"`
	RandomHost       bool              `proxy:"rand-host,omitempty"`
	RemoteDnsResolve bool              `proxy:"remote-dns-resolve,omitempty"`

	Flow              string         `proxy:"flow,omitempty"`
	ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`
	PacketEncoding    string         `proxy:"packet-encoding,omitempty"`
	PacketAddr        bool           `proxy:"packet-addr,omitempty"`
	XUDP              bool           `proxy:"xudp,omitempty"`
	RealityOpts       RealityOptions `proxy:"reality-opts,omitempty"`
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
			V2rayHTTPUpgrade:    v.option.WSOpts.V2rayHTTPUpgrade,
		}

		if len(v.option.WSOpts.Headers) != 0 {
			for key, value := range v.option.WSOpts.Headers {
				wsOpts.Headers.Add(key, value)
			}
		}

		if v.option.TLS {
			wsOpts.TLS = true
			tlsConfig := &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: v.option.SkipCertVerify,
				NextProtos:         []string{"http/1.1"},
			}
			if v.option.ServerName != "" {
				tlsConfig.ServerName = v.option.ServerName
				wsOpts.Host = v.option.ServerName
			} else if host1 := wsOpts.Headers.Get("Host"); host1 != "" {
				tlsConfig.ServerName = host1
				wsOpts.Host = host1
			}

			if v.lookupECH {
				v.lookupECH = resolver.SetECHConfigList(tlsConfig)
			}

			v.setECHConfig(tlsConfig)

			wsOpts.TLSConfig = tlsConfig
		} else if v.option.RandomHost || wsOpts.Headers.Get("Host") == "" {
			host1 := convert.RandHost()
			wsOpts.Host = host1
			wsOpts.Headers.Set("Host", host1)
		}

		if wsOpts.Headers.Get("User-Agent") == "" {
			wsOpts.Headers.Set("User-Agent", convert.RandUserAgent())
		}
		c, err = vmess.StreamWebsocketConn(c, wsOpts)
	case "http":
		host := v.option.Server
		// readability first, so just copy default TLS logic
		if v.option.TLS {
			tlsConfig := &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: v.option.SkipCertVerify,
			}

			if v.option.ServerName != "" {
				tlsConfig.ServerName = v.option.ServerName
			}

			if v.lookupECH {
				v.lookupECH = resolver.SetECHConfigList(tlsConfig)
			}

			v.setECHConfig(tlsConfig)

			c, err = tls2.StreamTLSConn(c, tlsConfig)
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
			maps.Copy(httpOpts.Headers, v.option.HTTPOpts.Headers)
		}

		if !v.option.TLS && (v.option.RandomHost || len(v.option.HTTPOpts.Headers["Host"]) == 0) {
			host1 := convert.RandHost()
			httpOpts.Host = host1
			httpOpts.Headers["Host"] = []string{host1}
		}

		if len(v.option.HTTPOpts.Headers["User-Agent"]) == 0 {
			httpOpts.Headers["User-Agent"] = []string{convert.RandUserAgent()}
		}
		c = h1.StreamHTTPConn(c, httpOpts)
	case "h2":
		tlsConfig := &tls.Config{
			NextProtos:         []string{"h2"},
			ServerName:         v.option.Server,
			InsecureSkipVerify: v.option.SkipCertVerify,
		}

		if v.option.ServerName != "" {
			tlsConfig.ServerName = v.option.ServerName
		}

		if v.lookupECH {
			v.lookupECH = resolver.SetECHConfigList(tlsConfig)
		}

		v.setECHConfig(tlsConfig)

		c, err = tls2.StreamTLSConn(c, tlsConfig)
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
		tlsConfig := v.gunTLSConfig
		if v.lookupECH {
			tlsConfig = v.gunTLSConfig.Clone()
			v.lookupECH = resolver.SetECHConfigList(tlsConfig)
		}
		c, err = gun.StreamGunWithConn(c, tlsConfig, v.gunConfig)
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

		serverName := quicOpts.Host
		if quicOpts.ServerName != "" {
			serverName = quicOpts.ServerName
		}

		tlsConfig := &tls.Config{
			NextProtos:         quicOpts.ALPN,
			ServerName:         serverName,
			InsecureSkipVerify: quicOpts.SkipCertVerify,
			MinVersion:         tls.VersionTLS13,
		}

		if v.lookupECH {
			v.lookupECH = resolver.SetECHConfigList(tlsConfig)
		}

		v.setECHConfig(tlsConfig)

		c, err = quic.StreamQUICConn(c, tlsConfig, quicOpts)
	default:
		// handle TLS
		if v.option.TLS {
			host, _, _ := net.SplitHostPort(v.addr)
			tlsConfig := &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: v.option.SkipCertVerify,
			}

			if v.option.ServerName != "" {
				tlsConfig.ServerName = v.option.ServerName
			}

			if v.lookupECH {
				v.lookupECH = resolver.SetECHConfigList(tlsConfig)
			}

			v.setECHConfig(tlsConfig)

			if v.realityConfig != nil {
				c, err = tls2.StreamRealityConn(c, tlsConfig, v.realityConfig)
			} else {
				c, err = tls2.StreamTLSConn(c, tlsConfig)
			}
		}
	}

	if err != nil {
		return nil, err
	}

	c, err = crypto.StreamAEADConnOrNot(c, v.option.AEADOpts)
	if err != nil {
		return nil, err
	}

	switch metadata.NetWork {
	case C.TCP:
		return v.client.DialEarlyConn(c, parseVlessAddr(metadata))
	case C.UDP:
		if v.option.XUDP {
			return v.client.DialEarlyXUDPPacketConn(c, parseVlessAddr(metadata))
		} else if v.option.PacketAddr {
			pc, err := v.client.DialEarlyPacketConn(c, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress, Port: 443})
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			if !metadata.Resolved() {
				rAddrs, err := resolver.LookupIP(context.Background(), metadata.Host)
				if err != nil {
					return c, fmt.Errorf("can't resolve ip, %w", err)
				}
				metadata.DstIP = rAddrs[0]
			}
			destination := parseVlessAddr(metadata)
			return packetaddr.NewConn(pc, destination), nil
		} else {
			if !metadata.Resolved() {
				rAddrs, err := resolver.LookupIP(context.Background(), metadata.Host)
				if err != nil {
					return c, fmt.Errorf("can't resolve ip, %w", err)
				}
				metadata.DstIP = rAddrs[0]
			}
			return v.client.DialEarlyPacketConn(c, parseVlessAddr(metadata))
		}
	default:
		_ = c.Close()
		return nil, net.UnknownNetworkError(metadata.NetWork.String())
	}
}

// StreamPacketConn implements C.ProxyAdapter
func (v *Vless) StreamPacketConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	c, err = v.StreamConn(c, metadata)
	if err != nil {
		return c, fmt.Errorf("new vless client error: %w", err)
	}
	return c, nil
}

// DialContext implements C.ProxyAdapter
func (v *Vless) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	var c net.Conn
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		tlsConfig := v.gunTLSConfig
		if v.lookupECH {
			tlsConfig = v.gunTLSConfig.Clone()
			v.lookupECH = resolver.SetECHConfigList(tlsConfig)
		}
		c, err = gun.StreamGunWithTransport(v.transport, tlsConfig, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func(cc net.Conn) {
			safeConnClose(cc, err)
		}(c)

		c, err = v.client.DialEarlyConn(c, parseVlessAddr(metadata))
		if err != nil {
			return nil, err
		}

		return NewConn(c, v), nil
	}

	c, err = v.dialContext(ctx, opts...)
	if err != nil {
		return nil, err
	}
	tcpKeepAlive(c)
	defer func(cc net.Conn) {
		safeConnClose(cc, err)
	}(c)

	c, err = v.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}
	return NewConn(c, v), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (v *Vless) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	var c net.Conn
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		tlsConfig := v.gunTLSConfig
		if v.lookupECH {
			tlsConfig = v.gunTLSConfig.Clone()
			v.lookupECH = resolver.SetECHConfigList(tlsConfig)
		}
		c, err = gun.StreamGunWithTransport(v.transport, tlsConfig, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func(cc net.Conn) {
			safeConnClose(cc, err)
		}(c)

		if v.option.XUDP {
			c, err = v.client.DialEarlyXUDPPacketConn(c, parseVlessAddr(metadata))
		} else if v.option.PacketAddr {
			pc, er := v.client.DialEarlyPacketConn(c, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress, Port: 443})
			if er != nil {
				return nil, er
			}
			if !metadata.Resolved() {
				rAddrs, err := resolver.LookupIP(context.Background(), metadata.Host)
				if err != nil {
					return nil, fmt.Errorf("can't resolve ip, %w", err)
				}
				metadata.DstIP = rAddrs[0]
			}
			c, err = packetaddr.NewConn(pc, parseVlessAddr(metadata)), nil
		} else {
			if !metadata.Resolved() {
				rAddrs, err := resolver.LookupIP(context.Background(), metadata.Host)
				if err != nil {
					return nil, fmt.Errorf("can't resolve ip, %w", err)
				}
				metadata.DstIP = rAddrs[0]
			}
			c, err = v.client.DialEarlyPacketConn(c, parseVlessAddr(metadata))
		}

		if err != nil {
			return nil, fmt.Errorf("new vless client error: %w", err)
		}

		return NewPacketConn(c.(net.PacketConn), v), nil
	}

	c, err = v.dialContext(ctx, opts...)
	if err != nil {
		return nil, err
	}

	tcpKeepAlive(c)
	defer func(cc net.Conn) {
		safeConnClose(cc, err)
	}(c)

	c, err = v.StreamPacketConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewPacketConn(c.(net.PacketConn), v), nil
}

func (v *Vless) dialContext(ctx context.Context, opts ...dialer.Option) (net.Conn, error) {
	switch v.option.Network {
	case "quic":
		c, err := dialer.ListenPacket(ctx, "udp", "", v.DialOptions(opts...)...)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", v.addr, err)
		}
		return c.(*net.UDPConn), nil
	}

	c, err := dialer.DialContext(ctx, "tcp", v.addr, v.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", v.addr, err)
	}
	return c, nil
}

func (v *Vless) setECHConfig(tlsConfig *tls.Config) {
	if v.echConfig != "" {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.InsecureSkipVerify = false
		tlsConfig.EncryptedClientHelloConfigList = []byte(v.echConfig)
		tlsConfig.EncryptedClientHelloRejectionVerify = func(state tls.ConnectionState) error {
			if !state.ECHAccepted {
				return resolver.ErrECHServerReject
			}
			return nil
		}
	}
}

func parseVlessAddr(metadata *C.Metadata) M.Socksaddr {
	if metadata.Resolved() {
		return M.Socksaddr{Addr: metadata.DstIP, Port: uint16(metadata.DstPort)}
	}
	return M.Socksaddr{Addr: metadata.DstIP, Fqdn: metadata.Host, Port: uint16(metadata.DstPort)}
}

func NewVless(option VlessOption) (*Vless, error) {
	if (option.Network != "ws" || option.WSOpts.V2rayHTTPUpgrade) && !option.TLS {
		return nil, errors.New("TLS must be true with tcp/http/h2/grpc/quic/httpupgrade network")
	}

	var (
		echConfig string
		lookupECH = option.ECH
	)
	if option.ECHConfig != "" {
		ech, err := base64.StdEncoding.DecodeString(option.ECHConfig)
		if err != nil {
			return nil, fmt.Errorf("invalid ECH config: %w", err)
		}
		echConfig = string(ech)
		lookupECH = false
	}

	if _, err := crypto.VerifyAEADOption(option.AEADOpts, true); err != nil {
		return nil, err
	}

	var realityConfig *tls2.RealityConfig
	if option.RealityOpts.PublicKey != "" {
		realityConfig = &tls2.RealityConfig{}
		publicKeyBytes, err := base64.RawURLEncoding.DecodeString(option.RealityOpts.PublicKey)
		if err != nil || len(publicKeyBytes) != 32 {
			return nil, errors.New("invalid reality public key")
		}
		realityConfig.PublicKey, err = ecdh.X25519().NewPublicKey(publicKeyBytes)
		if err != nil {
			return nil, err
		}
		if err != nil {
			return nil, fmt.Errorf("fail to create reality public key: %w", err)
		}

		n := hex.DecodedLen(len(option.RealityOpts.ShortID))
		if n > 8 {
			return nil, errors.New("invalid reality short ID")
		}

		n, err = hex.Decode(realityConfig.ShortID[:], []byte(option.RealityOpts.ShortID))
		if err != nil || n > 8 {
			return nil, errors.New("invalid reality short ID")
		}

		realityConfig.ClientHelloID = tls2.GetFingerprint(option.ClientFingerprint)
	}

	switch option.PacketEncoding {
	case "packetaddr", "packet":
		option.PacketAddr = true
		option.XUDP = false
	default:
		if !option.PacketAddr {
			option.XUDP = true
		}
	}
	if option.XUDP {
		option.PacketAddr = false
	}

	client, err := vless.NewClient(option.UUID, option.Flow, logger.NOP())
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
			rmark: option.RoutingMark,
			dns:   option.RemoteDnsResolve,
		},
		client:    client,
		option:    &option,
		echConfig: echConfig,
		lookupECH: lookupECH,

		realityConfig: realityConfig,
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
			c, err := dialer.DialContext(ctx, "tcp", v.addr, v.DialOptions()...)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %w", v.addr, err)
			}
			tcpKeepAlive(c)
			return c, nil
		}

		gunConfig := &gun.Config{
			ServiceName: v.option.GrpcOpts.GrpcServiceName,
			Host:        v.option.ServerName,
			DialFn:      dialFn,
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

		v.setECHConfig(tlsConfig)

		v.gunTLSConfig = tlsConfig
		v.gunConfig = gunConfig
		v.transport = gun.NewHTTP2Client()
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
