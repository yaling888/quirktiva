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
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/yaling888/clash/component/resolver"
)

const (
	// dotMimeType is the DoH mimetype that should be used.
	dotMimeType = "application/dns-message"
	userAgent   = "dns"
)

type retMsg struct {
	msg *D.Msg
	err error
}

type contextKey string

var _ dnsClient = (*dohClient)(nil)

type dohClient struct {
	r          *Resolver
	url        string
	host       string
	addr       string
	proxy      string
	urlLog     string
	forceHTTP3 bool
	transports sync.Map

	mux      sync.Mutex // guards following fields
	resolved bool
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

func (dc *dohClient) doRequest(req *http.Request, proxy string) (*D.Msg, error) {
	if tr, ok := dc.transports.Load(proxy); ok || dc.forceHTTP3 {
		if tr == nil {
			tr = newTransport(dc.host, true)
			if t, loaded := dc.transports.Swap(proxy, tr); loaded {
				closeTransport(t)
			}
		}
		return roundTrip(req, tr.(http.RoundTripper), false)
	}

	return dc.batchRoundTrip(req, proxy)
}

func (dc *dohClient) batchRoundTrip(req *http.Request, proxy string) (*D.Msg, error) {
	ch := dc.asyncRoundTripWithNewTransport(req, proxy, false)
	ch3 := dc.asyncRoundTripWithNewTransport(req, proxy, true)

	select {
	case rs := <-ch:
		return rs.msg, rs.err
	case rs := <-ch3:
		return rs.msg, rs.err
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

func (dc *dohClient) asyncRoundTripWithNewTransport(req *http.Request, proxy string, isH3 bool) <-chan *retMsg {
	ch := make(chan *retMsg, 1)

	go func() {
		newReq := new(http.Request)
		*newReq = *req
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				ch <- &retMsg{err: err}
				return
			}
			newReq.Body = body
		}

		if isH3 {
			newCtx := context.Background()
			if proxy != "" {
				newCtx = context.WithValue(newCtx, proxyKey, proxy)
			}
			ctx1, cancel := context.WithTimeout(newCtx, resolver.DefaultDNSTimeout)
			defer cancel()
			newReq = newReq.WithContext(ctx1)
		}

		tr := newTransport(dc.host, isH3)
		if proxy != "" && !isH3 {
			tr.(*http.Transport).IdleConnTimeout = 10 * time.Minute
		}

		msg, err := roundTrip(newReq, tr, true)
		if err == nil && isH3 {
			if t, loaded := dc.transports.Swap(proxy, tr); loaded {
				closeTransport(t)
			}
		} else if !isH3 {
			if _, loaded := dc.transports.LoadOrStore(proxy, tr); loaded {
				closeTransport(tr)
			}
		}

		ch <- &retMsg{msg: msg, err: err}
	}()

	return ch
}

func roundTrip(req *http.Request, transport http.RoundTripper, closed bool) (*D.Msg, error) {
	client1 := &http.Client{Transport: transport}
	if closed {
		defer client1.CloseIdleConnections()
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

	msg := &D.Msg{}
	err = msg.Unpack(buf)
	return msg, err
}

func newTransport(host string, isH3 bool) http.RoundTripper {
	if isH3 {
		return &http3.RoundTripper{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: host,
				NextProtos: []string{"dns"},
			},
			QuicConfig: &quic.Config{
				MaxIdleTimeout:       10 * time.Minute,
				KeepAlivePeriod:      15 * time.Second,
				HandshakeIdleTimeout: resolver.DefaultDNSTimeout,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				udpAddr, err := net.ResolveUDPAddr("udp", addr)
				if err != nil {
					return nil, err
				}

				pc, err := getPacketConn(ctx, addr)
				if err != nil {
					return nil, err
				}

				transport := &quic.Transport{Conn: pc}

				return transport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
			},
		}
	}

	return &http.Transport{
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return getTCPConn(ctx, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: host,
			NextProtos: []string{"dns"},
		},
		MaxIdleConnsPerHost: 5,
	}
}

func closeTransport(transport any) {
	switch tr := transport.(type) {
	case *http.Transport:
		tr.CloseIdleConnections()
	case *http3.RoundTripper:
		_ = tr.Close()
	}
}

func newDoHClient(url string, proxy string, forceHTTP3 bool, r *Resolver) *dohClient {
	u, _ := urlPkg.Parse(url)
	u.Scheme = "https"
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	addr := net.JoinHostPort(host, port)

	resolved := false
	if _, err := netip.ParseAddr(host); err == nil {
		resolved = true
	}

	return &dohClient{
		r:          r,
		url:        u.String(),
		host:       host,
		addr:       addr,
		proxy:      proxy,
		urlLog:     url,
		resolved:   resolved,
		forceHTTP3: forceHTTP3,
	}
}
