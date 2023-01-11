package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"

	D "github.com/miekg/dns"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
)

type client struct {
	*D.Client
	r            *Resolver
	port         string
	host         string
	iface        string
	proxyAdapter string
	ip           string
	isDHCP       bool
}

func (c *client) Exchange(m *D.Msg) (*D.Msg, error) {
	return c.ExchangeContext(context.Background(), m)
}

func (c *client) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	var err error
	if c.ip == "" {
		if c.r == nil {
			return nil, fmt.Errorf("dns %s not a valid ip", c.host)
		} else {
			var ips []netip.Addr
			ips, err = resolver.LookupIPByResolver(ctx, c.host, c.r)
			if err != nil {
				return nil, fmt.Errorf("use default dns resolve failed: %w", err)
			} else if len(ips) == 0 {
				return nil, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, c.host)
			}
			ip := ips[rand.Intn(len(ips))]
			c.ip = ip.String()
		}
	}

	network := "udp"
	if strings.HasPrefix(c.Client.Net, "tcp") {
		network = "tcp"
	}

	var (
		options []dialer.Option
		conn    net.Conn
	)
	if c.iface != "" {
		options = append(options, dialer.WithInterface(c.iface))
	}
	if c.proxyAdapter != "" {
		conn, err = dialContextWithProxyAdapter(ctx, c.proxyAdapter, network, netip.MustParseAddr(c.ip), c.port, options...)
		if err == errProxyNotFound {
			options = append(options[:0], dialer.WithInterface(c.proxyAdapter), dialer.WithRoutingMark(0))
			conn, err = dialer.DialContext(ctx, network, net.JoinHostPort(c.ip, c.port), options...)
		}
	} else {
		conn, err = dialer.DialContext(ctx, network, net.JoinHostPort(c.ip, c.port), options...)
	}

	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		if strings.HasSuffix(c.Client.Net, "tls") {
			conn = tls.Client(conn, c.Client.TLSConfig)
		}

		msg, _, err := c.Client.ExchangeWithConn(m, &D.Conn{
			Conn:         conn,
			UDPSize:      c.Client.UDPSize,
			TsigSecret:   c.Client.TsigSecret,
			TsigProvider: c.Client.TsigProvider,
		})

		ch <- result{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		clientNet := c.Client.Net
		if clientNet == "tcp-tls" {
			clientNet = "tls"
		} else if c.isDHCP {
			clientNet = "dhcp"
		}
		logDnsResponse(m.Question[0], ret.msg, clientNet, net.JoinHostPort(c.host, c.port), c.proxyAdapter)
		return ret.msg, ret.err
	}
}
