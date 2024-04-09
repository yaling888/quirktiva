package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	urlPkg "net/url"
	"sync"
	"time"

	D "github.com/miekg/dns"

	"github.com/yaling888/clash/component/resolver"
)

const (
	// dotMimeType is the DoH mimetype that should be used.
	dotMimeType = "application/dns-message"
	userAgent   = "dns"
)

type contextKey string

var _ dnsClient = (*dohClient)(nil)

type dohClient struct {
	r         *Resolver
	url       string
	addr      string
	proxy     string
	urlLog    string
	transport *http.Transport

	mux            sync.Mutex // guards following fields
	resolved       bool
	proxyTransport map[string]*http.Transport
}

func (dc *dohClient) IsLan() bool {
	return false
}

func (dc *dohClient) Exchange(m *D.Msg) (msg *rMsg, err error) {
	return dc.ExchangeContext(context.Background(), m)
}

func (dc *dohClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *rMsg, err error) {
	dc.mux.Lock()
	if !dc.resolved {
		host, port, _ := net.SplitHostPort(dc.addr)
		ips, err1 := resolver.LookupIPByResolver(context.Background(), host, dc.r)
		if err1 != nil {
			dc.mux.Unlock()
			return nil, err1
		}

		u, _ := urlPkg.Parse(dc.url)
		addr := net.JoinHostPort(ips[rand.IntN(len(ips))].String(), port)

		u.Host = addr
		dc.url = u.String()
		dc.addr = addr
		dc.resolved = true
	}
	dc.mux.Unlock()

	proxy := dc.proxy
	if p, ok := resolver.GetProxy(ctx); ok {
		proxy = p
	}

	msg = &rMsg{Source: dc.urlLog}
	if proxy != "" {
		msg.Source += "(" + proxy + ")"
		ctx = context.WithValue(ctx, proxyKey, proxy)
	}

	// https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
	// In order to maximize cache friendliness, SHOULD use a DNS ID of 0 in every DNS request.
	newM := *m
	newM.Id = 0
	req, err := dc.newRequest(&newM)
	if err != nil {
		return msg, err
	}

	var msg1 *D.Msg
	req = req.WithContext(ctx)
	msg1, err = dc.doRequest(req, proxy)
	if err == nil {
		msg1.Id = m.Id
		msg.Msg = msg1
	}
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
	req.Header.Set("user-agent", userAgent)
	return req, nil
}

func (dc *dohClient) doRequest(req *http.Request, proxy string) (msg *D.Msg, err error) {
	client1 := &http.Client{Transport: dc.getTransport(proxy)}
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

func (dc *dohClient) getTransport(proxy string) *http.Transport {
	if proxy == "" {
		return dc.transport
	}

	dc.mux.Lock()
	defer dc.mux.Unlock()

	if transport, ok := dc.proxyTransport[proxy]; ok {
		return transport
	}

	transport := &http.Transport{
		ForceAttemptHTTP2:   dc.transport.ForceAttemptHTTP2,
		DialContext:         dc.transport.DialContext,
		TLSClientConfig:     dc.transport.TLSClientConfig.Clone(),
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     10 * time.Minute,
	}

	dc.proxyTransport[proxy] = transport
	return transport
}

func newDoHClient(url string, proxy string, r *Resolver) *dohClient {
	u, _ := urlPkg.Parse(url)
	u.Scheme = "https"
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	var proxyTransport map[string]*http.Transport
	if proxy != "" {
		proxyTransport = make(map[string]*http.Transport)
	}

	resolved := false
	if _, err := netip.ParseAddr(host); err == nil {
		resolved = true
	}

	return &dohClient{
		r:        r,
		url:      u.String(),
		addr:     addr,
		proxy:    proxy,
		urlLog:   url,
		resolved: resolved,
		transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return getTCPConn(ctx, addr)
			},
			TLSClientConfig: &tls.Config{
				ServerName: host,
				NextProtos: []string{"dns"},
			},
			MaxIdleConnsPerHost: 5,
		},
		proxyTransport: proxyTransport,
	}
}
