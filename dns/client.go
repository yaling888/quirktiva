package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	D "github.com/miekg/dns"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
)

type client struct {
	*D.Client
	r      *Resolver
	port   string
	host   string
	iface  string
	proxy  string
	ip     string
	isDHCP bool
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
			ips, err = resolver.LookupIPByResolver(context.Background(), c.host, c.r)
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
		proxy   = c.proxy
	)

	if p, ok := resolver.GetProxy(ctx); ok {
		proxy = p
	}

	if c.iface != "" {
		options = append(options, dialer.WithInterface(c.iface))
	}

	if proxy != "" {
		conn, err = dialContextByProxyOrInterface(ctx, network, netip.MustParseAddr(c.ip), c.port, proxy, options...)
	} else {
		conn, err = dialer.DialContext(ctx, network, net.JoinHostPort(c.ip, c.port), options...)
	}

	if err != nil {
		return nil, err
	}

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}

	ch := make(chan result, 1)

	go func() {
		if c.Client.Net == "tcp-tls" {
			conn = tls.Client(conn, c.TLSConfig)
		}

		co := &D.Conn{
			Conn:         conn,
			UDPSize:      c.Client.UDPSize,
			TsigSecret:   c.Client.TsigSecret,
			TsigProvider: c.Client.TsigProvider,
		}

		msg, _, err2 := c.Client.ExchangeWithConn(m, co)

		ch <- result{msg, err2}

		_ = co.Close()
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
		logDnsResponse(m.Question[0], ret.msg, ret.err, clientNet, net.JoinHostPort(c.host, c.port), proxy)
		return ret.msg, ret.err
	}
}

func newClient(nw, addr, proxy, iface string, dhcp bool, r *Resolver) *client {
	host, port, _ := net.SplitHostPort(addr)
	var ip string
	if _, err := netip.ParseAddr(host); err == nil {
		ip = host
	}

	var timeout time.Duration
	if proxy != "" {
		timeout = proxyTimeout
	} else {
		timeout = resolver.DefaultDNSTimeout
	}

	return &client{
		Client: &D.Client{
			Net: nw,
			TLSConfig: &tls.Config{
				ServerName: host,
			},
			UDPSize: 4096,
			Timeout: timeout,
		},
		port:   port,
		host:   host,
		ip:     ip,
		iface:  iface,
		proxy:  proxy,
		isDHCP: dhcp,
		r:      r,
	}
}
