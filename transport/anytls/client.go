package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/yaling888/quirktiva/common/pool"
	"github.com/yaling888/quirktiva/component/dialer"
	"github.com/yaling888/quirktiva/component/resolver"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/anytls/padding"
	"github.com/yaling888/quirktiva/transport/anytls/session"
	tls2 "github.com/yaling888/quirktiva/transport/tls"
)

type ClientConfig struct {
	IdleSessionCheckInterval time.Duration
	IdleSessionTimeout       time.Duration
	MinIdleSession           int
	Server                   string
	Password                 string
	ALPN                     []string
	ServerName               string
	ClientFingerprint        string
	ECHConfig                string
	SkipCertVerify           bool
	LookupECH                bool
}

type Client struct {
	option         *ClientConfig
	passwordSha256 []byte
	server         string
	sessionClient  *session.Client
	padding        atomic.Pointer[padding.PaddingFactory]
	lookupECH      bool
}

func NewClient(ctx context.Context, config ClientConfig) *Client {
	pw := sha256.Sum256([]byte(config.Password))
	c := &Client{
		option:         &config,
		passwordSha256: pw[:],
		server:         config.Server,
		lookupECH:      config.LookupECH,
	}
	// Initialize the padding state of this client
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &c.padding)
	c.sessionClient = session.NewClient(ctx, c.createOutboundTLSConnection, &c.padding, config.IdleSessionCheckInterval, config.IdleSessionTimeout, config.MinIdleSession)
	return c
}

func (c *Client) CreateProxy(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (net.Conn, error) {
	strLen := len(metadata.Host)
	if strLen > 255 {
		return nil, errors.New("fqdn too long")
	}

	conn, err := c.sessionClient.CreateStream(ctx, opts...)
	if err != nil {
		return nil, err
	}

	b := pool.BufferWriter{}

	if metadata.Resolved() && metadata.NetWork == C.TCP {
		ip := metadata.DstIP.Unmap()
		if ip.Is4() {
			b.PutUint8(0x01)
		} else {
			b.PutUint8(0x04)
		}
		b.PutSlice(ip.AsSlice())
	} else {
		b.PutUint8(0x03)
		b.PutUint8(uint8(strLen))
		b.PutString(metadata.Host)
	}

	b.PutUint16be(uint16(metadata.DstPort))

	if _, err = conn.Write(b.Bytes()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) createOutboundTLSConnection(ctx context.Context, opts ...dialer.Option) (net.Conn, error) {
	conn, err := dialer.DialContext(ctx, "tcp", c.server, opts...)
	if err != nil {
		return nil, err
	}

	b := pool.BufferWriter{}
	b.PutSlice(c.passwordSha256)

	var paddingLen int
	if pad := c.padding.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
		paddingLen = pad[0]
	}

	b.PutUint16be(uint16(paddingLen))
	if paddingLen > 0 {
		b.WriteZeroN(paddingLen)
	}

	tlsConfig := &tls.Config{
		NextProtos:         c.option.ALPN,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.option.SkipCertVerify,
		ServerName:         c.option.ServerName,
	}

	if c.lookupECH {
		c.lookupECH = resolver.SetECHConfigList(tlsConfig)
	}

	c.setECHConfig(tlsConfig)

	tlsConn, err := tls2.StreamContextConn(ctx, conn, tlsConfig, c.option.ClientFingerprint)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	_, err = b.WriteTo(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (c *Client) Close() error {
	return c.sessionClient.Close()
}

func (c *Client) setECHConfig(tlsConfig *tls.Config) {
	if c.option.ECHConfig != "" {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.InsecureSkipVerify = false
		tlsConfig.EncryptedClientHelloConfigList = []byte(c.option.ECHConfig)
		tlsConfig.EncryptedClientHelloRejectionVerify = func(state tls.ConnectionState) error {
			if !state.ECHAccepted {
				return resolver.ErrECHServerReject
			}
			return nil
		}
	}
}
