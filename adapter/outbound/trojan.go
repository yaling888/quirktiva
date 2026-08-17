package outbound

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/yaling888/quirktiva/common/convert"
	"github.com/yaling888/quirktiva/component/dialer"
	"github.com/yaling888/quirktiva/component/resolver"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/crypto"
	"github.com/yaling888/quirktiva/transport/gun"
	"github.com/yaling888/quirktiva/transport/header"
	"github.com/yaling888/quirktiva/transport/quic"
	"github.com/yaling888/quirktiva/transport/trojan"
)

var _ C.ProxyAdapter = (*Trojan)(nil)

type Trojan struct {
	*Base
	instance *trojan.Trojan
	option   *TrojanOption

	// for gun mux
	gunTLSConfig *tls.Config
	gunConfig    *gun.Config
	transport    *http.Transport

	quicAEAD  *crypto.AEAD
	echConfig string
	lookupECH bool
}

type TrojanOption struct {
	BasicOption
	Name             string            `proxy:"name"`
	Server           string            `proxy:"server"`
	Port             int               `proxy:"port"`
	Password         string            `proxy:"password"`
	ALPN             []string          `proxy:"alpn,omitempty"`
	SNI              string            `proxy:"sni,omitempty"`
	ECHConfig        string            `proxy:"ech-config,omitempty"`
	ECH              bool              `proxy:"ech,omitempty"`
	SkipCertVerify   bool              `proxy:"skip-cert-verify,omitempty"`
	UDP              bool              `proxy:"udp,omitempty"`
	Network          string            `proxy:"network,omitempty"`
	GrpcOpts         GrpcOptions       `proxy:"grpc-opts,omitempty"`
	WSOpts           WSOptions         `proxy:"ws-opts,omitempty"`
	HTTP2Opts        HTTP2Options      `proxy:"h2-opts,omitempty"`
	QUICOpts         QUICOptions       `proxy:"quic-opts,omitempty"`
	AEADOpts         crypto.AEADOption `proxy:"aead-opts,omitempty"`
	RemoteDnsResolve bool              `proxy:"remote-dns-resolve,omitempty"`
}

func (t *Trojan) plainStream(conn net.Conn) (net.Conn, error) {
	switch t.option.Network {
	case "ws":
		host, port, _ := net.SplitHostPort(t.addr)
		wsOpts := &trojan.WebsocketOption{
			Host:             host,
			Port:             port,
			Path:             t.option.WSOpts.Path,
			Headers:          http.Header{},
			V2rayHTTPUpgrade: t.option.WSOpts.V2rayHTTPUpgrade,
		}

		if t.option.SNI != "" {
			wsOpts.Host = t.option.SNI
		}

		if len(t.option.WSOpts.Headers) != 0 {
			for key, value := range t.option.WSOpts.Headers {
				wsOpts.Headers.Add(key, value)
			}
		}

		if wsOpts.Headers.Get("User-Agent") == "" {
			wsOpts.Headers.Set("User-Agent", convert.RandUserAgent())
		}

		return t.instance.StreamWebsocketConn(conn, wsOpts)
	case "h2":
		h2Opts := &trojan.HTTPOptions{
			Hosts:   t.option.HTTP2Opts.Host,
			Path:    t.option.HTTP2Opts.Path,
			Headers: http.Header{},
		}

		if len(t.option.HTTP2Opts.Headers) != 0 {
			for key, value := range t.option.HTTP2Opts.Headers {
				h2Opts.Headers.Add(key, value)
			}
		}

		if h2Opts.Headers.Get("User-Agent") == "" {
			h2Opts.Headers.Set("User-Agent", convert.RandUserAgent())
		}

		return t.instance.StreamH2Conn(conn, h2Opts)
	case "quic":
		quicOpts := &quic.Config{
			Host:           t.option.Server,
			Port:           t.option.Port,
			ALPN:           t.option.ALPN,
			ServerName:     t.option.Server,
			SkipCertVerify: t.option.SkipCertVerify,
			Header:         t.option.QUICOpts.Header,
			AEAD:           t.quicAEAD,
		}

		if t.option.SNI != "" {
			quicOpts.ServerName = t.option.SNI
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

		if t.lookupECH {
			t.lookupECH = resolver.SetECHConfigList(tlsConfig)
		}

		t.setECHConfig(tlsConfig)

		return quic.StreamQUICConn(conn, tlsConfig, quicOpts)
	}

	return t.instance.StreamConn(conn)
}

func (t *Trojan) trojanStream(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	if t.transport != nil {
		tlsConfig := t.gunTLSConfig
		if t.lookupECH {
			tlsConfig = t.gunTLSConfig.Clone()
			t.lookupECH = resolver.SetECHConfigList(tlsConfig)
		}
		c, err = gun.StreamGunWithConn(c, tlsConfig, t.gunConfig)
	} else {
		c, err = t.plainStream(c)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
		}
		c, err = crypto.StreamAEADConnOrNot(c, t.option.AEADOpts)
	}

	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}

	if metadata.NetWork == C.UDP {
		err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata))
		return c, err
	}

	err = t.instance.WriteHeader(c, trojan.CommandTCP, serializesSocksAddr(metadata))
	return c, err
}

// StreamConn implements C.ProxyAdapter
func (t *Trojan) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	return t.trojanStream(c, metadata)
}

// StreamPacketConn implements C.ProxyAdapter
func (t *Trojan) StreamPacketConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	c, err = t.trojanStream(c, metadata)
	if err != nil {
		return c, err
	}

	pc := t.instance.PacketConn(c)
	return WrapConn(pc), nil
}

// DialContext implements C.ProxyAdapter
func (t *Trojan) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	var c net.Conn

	// gun transport
	if t.transport != nil && len(opts) == 0 {
		tlsConfig := t.gunTLSConfig
		if t.lookupECH {
			tlsConfig = t.gunTLSConfig.Clone()
			t.lookupECH = resolver.SetECHConfigList(tlsConfig)
		}
		c, err = gun.StreamGunWithTransport(t.transport, tlsConfig, t.gunConfig)
		if err != nil {
			return nil, err
		}

		defer func(cc net.Conn) {
			safeConnClose(cc, err)
		}(c)

		if err = t.instance.WriteHeader(c, trojan.CommandTCP, serializesSocksAddr(metadata)); err != nil {
			return nil, err
		}

		return NewConn(c, t), nil
	}

	c, err = t.dialContext(ctx, opts...)
	if err != nil {
		return nil, err
	}
	tcpKeepAlive(c)

	defer func(cc net.Conn) {
		safeConnClose(cc, err)
	}(c)

	c, err = t.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, t), err
}

// ListenPacketContext implements C.ProxyAdapter
func (t *Trojan) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	var c net.Conn

	// gun transport
	if t.transport != nil && len(opts) == 0 {
		tlsConfig := t.gunTLSConfig
		if t.lookupECH {
			tlsConfig = t.gunTLSConfig.Clone()
			t.lookupECH = resolver.SetECHConfigList(tlsConfig)
		}
		c, err = gun.StreamGunWithTransport(t.transport, tlsConfig, t.gunConfig)
		if err != nil {
			return nil, err
		}

		defer func(cc net.Conn) {
			safeConnClose(cc, err)
		}(c)

		if err = t.instance.WriteHeader(c, trojan.CommandUDP, serializesSocksAddr(metadata)); err != nil {
			return nil, err
		}

		pc := t.instance.PacketConn(c)

		return NewPacketConn(pc, t), nil
	}

	c, err = t.dialContext(ctx, opts...)
	if err != nil {
		return nil, err
	}

	tcpKeepAlive(c)

	defer func(cc net.Conn) {
		safeConnClose(cc, err)
	}(c)

	c, err = t.StreamPacketConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewPacketConn(c.(net.PacketConn), t), nil
}

func (t *Trojan) dialContext(ctx context.Context, opts ...dialer.Option) (net.Conn, error) {
	switch t.option.Network {
	case "quic":
		c, err := dialer.ListenPacket(ctx, "udp", "", t.DialOptions(opts...)...)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
		}
		return c.(*net.UDPConn), nil
	}

	c, err := dialer.DialContext(ctx, "tcp", t.addr, t.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
	}
	return c, nil
}

func (t *Trojan) setECHConfig(tlsConfig *tls.Config) {
	if t.echConfig != "" {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.InsecureSkipVerify = false
		tlsConfig.EncryptedClientHelloConfigList = []byte(t.echConfig)
		tlsConfig.EncryptedClientHelloRejectionVerify = func(state tls.ConnectionState) error {
			if !state.ECHAccepted {
				return resolver.ErrECHServerReject
			}
			return nil
		}
	}
}

func NewTrojan(option TrojanOption) (*Trojan, error) {
	if _, err := crypto.VerifyAEADOption(option.AEADOpts, true); err != nil {
		return nil, err
	}

	var (
		echConfig string
		lookupECH = option.ECH
	)
	if option.ECHConfig != "" {
		ech, err := base64.StdEncoding.DecodeString(option.ECHConfig)
		if err != nil {
			ech, err = base64.URLEncoding.DecodeString(option.ECHConfig)
			if err != nil {
				return nil, fmt.Errorf("invalid ECH config: %w", err)
			}
		}
		echConfig = string(ech)
		lookupECH = false
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))

	tOption := &trojan.Option{
		Password:       option.Password,
		ALPN:           option.ALPN,
		ServerName:     option.Server,
		ECHConfig:      echConfig,
		SkipCertVerify: option.SkipCertVerify,
		LookupECH:      lookupECH,
	}

	if option.SNI != "" {
		tOption.ServerName = option.SNI
	}

	t := &Trojan{
		Base: &Base{
			name:  option.Name,
			addr:  addr,
			tp:    C.Trojan,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
			dns:   option.RemoteDnsResolve,
		},
		instance:  trojan.New(tOption),
		option:    &option,
		echConfig: echConfig,
		lookupECH: lookupECH,
	}

	switch option.Network {
	case "h2":
		if len(option.HTTP2Opts.Host) == 0 {
			option.HTTP2Opts.Host = append(option.HTTP2Opts.Host, tOption.ServerName)
		}
	case "grpc":
		dialFn := func(_, _ string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
			defer cancel()
			c, err := dialer.DialContext(ctx, "tcp", t.addr, t.DialOptions()...)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %w", t.addr, err)
			}
			tcpKeepAlive(c)
			return c, nil
		}

		tlsConfig := &tls.Config{
			NextProtos:         option.ALPN,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: tOption.SkipCertVerify,
			ServerName:         tOption.ServerName,
		}

		t.setECHConfig(tlsConfig)

		t.transport = gun.NewHTTP2Client()

		t.gunTLSConfig = tlsConfig
		t.gunConfig = &gun.Config{
			ServiceName: option.GrpcOpts.GrpcServiceName,
			Host:        tOption.ServerName,
			DialFn:      dialFn,
		}
	case "quic":
		quicAEAD, err := crypto.NewAEAD(t.option.QUICOpts.Security, t.option.QUICOpts.Key, "v2ray-quic-salt")
		if err != nil {
			return nil, fmt.Errorf("invalid quic-opts: %w", err)
		}
		t.quicAEAD = quicAEAD
		_, err = header.New(t.option.QUICOpts.Header)
		if err != nil {
			return nil, fmt.Errorf("invalid quic-opts: %w", err)
		}
	}

	return t, nil
}
