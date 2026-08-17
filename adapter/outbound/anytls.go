package outbound

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/yaling888/quirktiva/component/dialer"
	"github.com/yaling888/quirktiva/component/resolver"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/anytls"
)

type AnyTLS struct {
	*Base
	client *anytls.Client
	option *AnyTLSOption

	echConfig string //nolint: unused
	lookupECH bool   //nolint: unused
}

type AnyTLSOption struct {
	BasicOption
	Name                     string   `proxy:"name"`
	Server                   string   `proxy:"server"`
	Port                     int      `proxy:"port"`
	Password                 string   `proxy:"password"`
	ALPN                     []string `proxy:"alpn,omitempty"`
	SNI                      string   `proxy:"sni,omitempty"`
	ECHConfig                string   `proxy:"ech-config,omitempty"`
	ECH                      bool     `proxy:"ech,omitempty"`
	SkipCertVerify           bool     `proxy:"skip-cert-verify,omitempty"`
	UDP                      bool     `proxy:"udp,omitempty"`
	IdleSessionCheckInterval int      `proxy:"idle-session-check-interval,omitempty"`
	IdleSessionTimeout       int      `proxy:"idle-session-timeout,omitempty"`
	MinIdleSession           int      `proxy:"min-idle-session,omitempty"`
	RemoteDnsResolve         bool     `proxy:"remote-dns-resolve,omitempty"`
}

func (t *AnyTLS) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	c, err := t.client.CreateProxy(ctx, metadata, t.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}
	return NewConn(c, t), nil
}

func (t *AnyTLS) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	if !metadata.Resolved() {
		rAddrs, err := resolver.LookupIP(context.Background(), metadata.Host)
		if err != nil {
			return nil, fmt.Errorf("can't resolve ip, %w", err)
		}
		metadata.DstIP = rAddrs[0]
	}

	md := *metadata
	md.Host = "sp.v2.udp-over-tcp.arpa"
	c, err := t.client.CreateProxy(ctx, &md, t.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}

	destination := M.SocksaddrFromNet(metadata.UDPAddr())
	return NewPacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination}), t), nil
}

// Cleanup implements C.ProxyAdapter
func (t *AnyTLS) Cleanup() {
	_ = t.client.Close()
}

func NewAnyTLS(option AnyTLSOption) (*AnyTLS, error) {
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
	outbound := &AnyTLS{
		Base: &Base{
			name:  option.Name,
			addr:  addr,
			tp:    C.AnyTLS,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
			dns:   option.RemoteDnsResolve,
		},
		option: &option,
	}

	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	alpn := option.ALPN
	if len(alpn) == 0 {
		alpn = []string{"h2, http/1.1"}
	}

	tOption := anytls.ClientConfig{
		Password:                 option.Password,
		Server:                   addr,
		IdleSessionCheckInterval: time.Duration(option.IdleSessionCheckInterval) * time.Second,
		IdleSessionTimeout:       time.Duration(option.IdleSessionTimeout) * time.Second,
		MinIdleSession:           option.MinIdleSession,
		SkipCertVerify:           option.SkipCertVerify,
		ALPN:                     alpn,
		ServerName:               serverName,
		ECHConfig:                echConfig,
		LookupECH:                lookupECH,
	}

	client := anytls.NewClient(context.TODO(), tOption)
	outbound.client = client

	return outbound, nil
}
