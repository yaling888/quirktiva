package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	urlPkg "net/url"
	"time"

	D "github.com/miekg/dns"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/tunnel"
)

const (
	// dotMimeType is the DoH mimetype that should be used.
	dotMimeType = "application/dns-message"

	proxyKey     = contextKey("key-doh-proxy")
	proxyTimeout = 10 * time.Second
)

type contextKey string

type dohClient struct {
	r         *Resolver
	url       string
	addr      string
	proxy     string
	timeout   time.Duration
	transport *http.Transport
}

func (dc *dohClient) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return dc.ExchangeContext(context.Background(), m)
}

func (dc *dohClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	// https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
	// In order to maximize cache friendliness, SHOULD use a DNS ID of 0 in every DNS request.
	newM := *m
	newM.Id = 0
	req, err := dc.newRequest(&newM)
	if err != nil {
		return nil, err
	}

	var (
		proxy    = dc.proxy
		hasProxy bool
	)

	if p, ok := resolver.GetProxy(ctx); ok {
		proxy = p
	}

	if proxy != "" {
		_, hasProxy = tunnel.FindProxyByName(proxy)
		ctx = context.WithValue(ctx, proxyKey, proxy)
	}

	if _, ok := ctx.Deadline(); !ok {
		subCtx, cancel := context.WithTimeout(ctx, dc.timeout)
		defer cancel()
		ctx = subCtx
	}

	req = req.WithContext(ctx)
	msg, err = dc.doRequest(ctx, req, hasProxy)
	if err == nil {
		msg.Id = m.Id
	}
	logDnsResponse(m.Question[0], msg, err, "", dc.url, proxy)
	return
}

// newRequest returns a new DoH request given a dns.Msg.
func (dc *dohClient) newRequest(m *D.Msg) (*http.Request, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, dc.url, bytes.NewReader(buf))
	if err != nil {
		return req, err
	}

	req.Header.Set("content-type", dotMimeType)
	req.Header.Set("accept", dotMimeType)
	return req, nil
}

func (dc *dohClient) doRequest(ctx context.Context, req *http.Request, hasProxy bool) (msg *D.Msg, err error) {
	var client1 *http.Client
	if hasProxy {
		conn, err1 := getConn(ctx, dc.r, dc.addr)
		if err1 != nil {
			return nil, err1
		}
		defer conn.Close()
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				return conn, nil
			},
			TLSClientConfig:     dc.transport.TLSClientConfig,
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
			MaxConnsPerHost:     1,
			IdleConnTimeout:     1 * time.Second,
		}
		client1 = &http.Client{Transport: transport}
		defer client1.CloseIdleConnections()
	} else {
		client1 = &http.Client{Transport: dc.transport}
	}

	resp, err := client1.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	msg = &D.Msg{}
	err = msg.Unpack(buf)
	return msg, err
}

func newDoHClient(url string, proxy string, r *Resolver) *dohClient {
	u, _ := urlPkg.Parse(url)
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(u.Hostname(), port)

	var timeout time.Duration
	if proxy != "" {
		timeout = proxyTimeout
	} else {
		timeout = resolver.DefaultDNSTimeout
	}

	return &dohClient{
		r:       r,
		url:     url,
		addr:    addr,
		proxy:   proxy,
		timeout: timeout,
		transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return getConn(ctx, r, addr)
			},
			TLSClientConfig: &tls.Config{
				NextProtos: []string{"dns"},
			},
		},
	}
}

func getConn(ctx context.Context, r *Resolver, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := resolver.LookupIPByResolver(context.Background(), host, r)
	if err != nil {
		return nil, err
	}
	ip := ips[0]

	if proxy, ok := ctx.Value(proxyKey).(string); ok {
		return dialContextByProxyOrInterface(ctx, "tcp", ip, port, proxy)
	}

	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
}
