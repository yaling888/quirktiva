package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	urlPkg "net/url"
	"sync"
	"time"

	D "github.com/miekg/dns"

	"github.com/Dreamacro/clash/component/resolver"
)

const (
	// dotMimeType is the DoH mimetype that should be used.
	dotMimeType = "application/dns-message"
)

type contextKey string

type dohClient struct {
	r         *Resolver
	url       string
	addr      string
	proxy     string
	urlLog    string
	timeout   time.Duration
	transport *http.Transport

	mux            sync.Mutex // guards following fields
	resolved       bool
	proxyTransport map[string]*http.Transport
}

func (dc *dohClient) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return dc.ExchangeContext(context.Background(), m)
}

func (dc *dohClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	dc.mux.Lock()
	if !dc.resolved {
		host, port, _ := net.SplitHostPort(dc.addr)
		ips, err1 := resolver.LookupIPByResolver(context.Background(), host, dc.r)
		if err1 != nil {
			dc.mux.Unlock()
			return nil, err1
		}

		u, _ := urlPkg.Parse(dc.url)
		addr := net.JoinHostPort(ips[rand.Intn(len(ips))].String(), port)

		u.Host = addr
		dc.url = u.String()
		dc.addr = addr
		dc.resolved = true
	}
	dc.mux.Unlock()

	// https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
	// In order to maximize cache friendliness, SHOULD use a DNS ID of 0 in every DNS request.
	newM := *m
	newM.Id = 0
	req, err := dc.newRequest(&newM)
	if err != nil {
		return nil, err
	}

	proxy := dc.proxy
	if p, ok := resolver.GetProxy(ctx); ok {
		proxy = p
	}

	if proxy != "" {
		ctx = context.WithValue(ctx, proxyKey, proxy)
	}

	if _, ok := ctx.Deadline(); !ok {
		subCtx, cancel := context.WithTimeout(ctx, dc.timeout)
		defer cancel()
		ctx = subCtx
	}

	req = req.WithContext(ctx)
	msg, err = dc.doRequest(req, proxy)
	if err == nil {
		msg.Id = m.Id
	}
	logDnsResponse(m.Question[0], msg, err, "", dc.urlLog, proxy)
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
	if transport, ok := dc.proxyTransport[proxy]; ok {
		dc.mux.Unlock()
		return transport
	}

	transport := &http.Transport{
		ForceAttemptHTTP2:   dc.transport.ForceAttemptHTTP2,
		DialContext:         dc.transport.DialContext,
		TLSClientConfig:     dc.transport.TLSClientConfig.Clone(),
		TLSHandshakeTimeout: dc.transport.TLSHandshakeTimeout,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     10 * time.Minute,
	}

	dc.proxyTransport[proxy] = transport
	dc.mux.Unlock()

	return transport
}

func newDoHClient(url string, proxy string, r *Resolver) *dohClient {
	u, _ := urlPkg.Parse(url)
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	var (
		timeout        time.Duration
		proxyTransport map[string]*http.Transport
	)

	if proxy != "" {
		timeout = proxyTimeout
		proxyTransport = make(map[string]*http.Transport)
	} else {
		timeout = resolver.DefaultDNSTimeout
	}

	resolved := false
	if _, err := netip.ParseAddr(host); err == nil {
		resolved = true
	}

	return &dohClient{
		r:        r,
		url:      url,
		addr:     addr,
		proxy:    proxy,
		urlLog:   url,
		resolved: resolved,
		timeout:  timeout,
		transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return getTCPConn(ctx, addr)
			},
			TLSClientConfig: &tls.Config{
				ServerName: host,
				NextProtos: []string{"dns"},
			},
			TLSHandshakeTimeout: timeout,
			MaxIdleConnsPerHost: 5,
		},
		proxyTransport: proxyTransport,
	}
}
