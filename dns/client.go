package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"

	D "github.com/miekg/dns"

	"github.com/yaling888/quirktiva/component/dialer"
	"github.com/yaling888/quirktiva/component/resolver"
)

var _ dnsClient = (*client)(nil)

type client struct {
	*D.Client
	r      *Resolver
	port   string
	host   string
	iface  string
	proxy  string
	ip     string
	lan    bool
	source string
}

func (c *client) IsLan() bool {
	return c.lan
}

func (c *client) Exchange(m *D.Msg) (*rMsg, error) {
	return c.ExchangeContext(context.Background(), m)
}

func (c *client) ExchangeContext(ctx context.Context, m *D.Msg) (*rMsg, error) {
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
			ip := ips[rand.IntN(len(ips))]
			c.ip = ip.String()
			c.lan = ip.IsLoopback() || ip.IsPrivate()
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
		msg     = &rMsg{Source: c.source, Lan: c.lan}
	)

	if p, ok := resolver.GetProxy(ctx); ok && !c.lan {
		proxy = p
	}

	if c.iface != "" {
		options = append(options, dialer.WithInterface(c.iface))
	}

	if proxy != "" {
		msg.Source += "(" + proxy + ")"
		conn, err = dialContextByProxyOrInterface(ctx, network, netip.MustParseAddr(c.ip), c.port, proxy, options...)
	} else {
		conn, err = dialer.DialContext(ctx, network, net.JoinHostPort(c.ip, c.port), options...)
	}

	if err != nil {
		return msg, err
	}

	if c.Client.Net == "tcp-tls" {
		conn = tls.Client(conn, c.TLSConfig)
	}

	co := &D.Conn{
		Conn:         conn,
		UDPSize:      c.Client.UDPSize,
		TsigSecret:   c.Client.TsigSecret,
		TsigProvider: c.Client.TsigProvider,
	}

	defer co.Close()

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}

	ch := make(chan result, 1)

	go func() {
		msg1, _, err1 := c.Client.ExchangeWithConn(m, co)
		ch <- result{msg1, err1}
	}()

	select {
	case <-ctx.Done():
		return msg, ctx.Err()
	case ret := <-ch:
		msg.Msg = ret.msg
		return msg, ret.err
	}
}

func newClient(nw, addr, proxy, iface string, dhcp bool, r *Resolver) *client {
	host, port, _ := net.SplitHostPort(addr)
	var (
		ip  string
		lan bool
	)
	if a, err := netip.ParseAddr(host); err == nil {
		ip = host
		lan = a.IsLoopback() || a.IsPrivate()
	}

	var timeout time.Duration
	if proxy != "" {
		timeout = proxyTimeout
	} else {
		timeout = resolver.DefaultDNSTimeout
	}

	clientNet := nw
	if dhcp {
		clientNet = "dhcp"
	} else if clientNet == "tcp-tls" {
		clientNet = "tls"
	}
	if clientNet != "" {
		clientNet += "://"
	}
	source := clientNet + addr

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
		source: source,
		lan:    lan,
		r:      r,
	}
}
