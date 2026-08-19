package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	urlPkg "net/url"
	"strconv"
	"sync"
	"time"

	D "github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/yaling888/quirktiva/common/context2"
	"github.com/yaling888/quirktiva/component/resolver"
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
		ctx = resolver.WithoutProxy(ctx) // clean up context value before dial conn, prevent loop call
		if proxy == "" || proxy == remoteResolverKey {
			proxy = p
		}
	} else if proxy == remoteResolverKey {
		return nil, fmt.Errorf("doh-client: no proxy for %s", dc.urlLog)
	}
	if resolver.IsProxyServer(ctx) {
		ctx = resolver.WithoutProxyServer(ctx) // clean up context value before dial conn, prevent loop call
	}

	msg = &rMsg{Source: dc.urlLog}
	if proxy != "" {
		msg.Source += "(" + proxy + ")"
		ctx = context.WithValue(ctx, proxyKey, proxy)
	} else if ctx.Value(proxyKey) != nil {
		ctx = context.WithValue(ctx, proxyKey, nil) // clean up context value before dial conn, prevent loop call
	}

	// https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
	// In order to maximize cache friendliness, SHOULD use a DNS ID of 0 in every DNS request.
	newM := *m
	newM.Id = 0
	req, err := dc.newRequest(ctx, &newM)
	if err != nil {
		return msg, err
	}

	var msg1 *D.Msg
	msg1, err = dc.doRequest(ctx, req, proxy)
	if err == nil {
		msg1.Id = m.Id
		msg.Msg = msg1
	}
	return
}

// newRequest returns a new DoH request given a dns.Msg.
func (dc *dohClient) newRequest(ctx context.Context, m *D.Msg) (*http.Request, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dc.url, bytes.NewReader(buf))
	if err != nil {
		return req, err
	}

	req.Header.Set("content-type", dotMimeType)
	req.Header.Set("accept", dotMimeType)
	req.Header.Set("user-agent", userAgent)
	return req, nil
}

func (dc *dohClient) doRequest(ctx context.Context, req *http.Request, proxy string) (*D.Msg, error) {
	if tr, ok := dc.transports.Load(proxy); ok || dc.forceHTTP3 {
		if !ok {
			tr = dc.newTransport(true)
			if t, loaded := dc.transports.Swap(proxy, tr); loaded {
				closeTransport(t)
			}
		}
		return roundTrip(ctx, req, tr.(http.RoundTripper), proxy)
	}

	return dc.batchRoundTrip(ctx, req, proxy)
}

func (dc *dohClient) batchRoundTrip(ctx context.Context, req *http.Request, proxy string) (*D.Msg, error) {
	ctx1, cancel := context.WithCancelCause(ctx)
	defer cancel(context2.ManualCanceled)

	select {
	case rs := <-dc.asyncRoundTripWithNewTransport(ctx1, req, proxy, true):
		return rs.msg, rs.err
	case rs := <-dc.asyncRoundTripWithNewTransport(ctx1, req, proxy, false):
		return rs.msg, rs.err
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

func (dc *dohClient) asyncRoundTripWithNewTransport(ctx context.Context, req *http.Request, proxy string, isH3 bool) <-chan *retMsg {
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

		tr := dc.newTransport(isH3)
		if proxy != "" {
			if t, ok := tr.(*http.Transport); ok {
				t.IdleConnTimeout = 10 * time.Minute
			}
		}

		msg, err := roundTrip(ctx, newReq, tr, proxy)
		if err == nil {
			switch t := tr.(type) {
			case *http.Transport:
				if p, loaded := dc.transports.Swap(proxy, t); loaded {
					if _, ok := p.(*http3Transport); ok {
						// swap back, priority use http3 transport if server present
						if p, loaded = dc.transports.Swap(proxy, p); loaded {
							closeTransport(p)
						}
						closeTransport(t)
					} else {
						closeTransport(p)
					}
				}
			case *http3Transport:
				if p, loaded := dc.transports.Swap(proxy, t); loaded {
					closeTransport(p)
				}
			}
		}

		ch <- &retMsg{msg: msg, err: err}
	}()

	return ch
}

func (dc *dohClient) newTransport(isH3 bool) http.RoundTripper {
	if isH3 {
		return newHttp3Transport(dc.host, dc.forceHTTP3)
	}

	return &http.Transport{
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(dc.addr)
			if err != nil {
				return nil, err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return nil, err
			}
			portNum, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, err
			}
			return getTCPConn(ctx, netip.AddrPortFrom(ip, uint16(portNum)))
		},
		TLSClientConfig: &tls.Config{
			ServerName: dc.host,
			NextProtos: []string{"dns"},
		},
		MaxIdleConnsPerHost: 5,
	}
}

func roundTrip(ctx context.Context, req *http.Request, transport http.RoundTripper, proxy string) (*D.Msg, error) {
	timeout := resolver.DefaultDNSTimeout
	if proxy != "" {
		timeout = proxyTimeout
	}
	ctx1, cancel := context2.WithTimeoutCause(ctx, timeout, context2.ManualCanceled)
	defer cancel()
	req = req.WithContext(ctx1)

	client1 := &http.Client{Transport: transport, Timeout: timeout}
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

func closeTransport(transport any) {
	switch tr := transport.(type) {
	case *http.Transport:
		tr.CloseIdleConnections()
	case *http3Transport:
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

type http3Transport struct {
	roundTripper *http3.Transport
	forceHTTP3   bool

	mux       sync.Mutex
	transport *quic.Transport
	isUDPConn bool
}

func (t *http3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.roundTripper.RoundTrip(req)
}

func (t *http3Transport) Close() error {
	err := t.roundTripper.Close()
	t.mux.Lock()
	defer t.mux.Unlock()
	if t.transport != nil {
		_ = t.transport.Close()
		_ = t.transport.Conn.Close()
		t.transport = nil
	}
	return err
}

func (t *http3Transport) CloseIdleConnections() {
	t.roundTripper.CloseIdleConnections()
}

func (t *http3Transport) makeDialer() func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return nil, err
		}
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, err
		}
		udpAddr := &net.UDPAddr{IP: ip.AsSlice(), Port: int(p)}

		t.mux.Lock()
		transport := t.transport
		if transport == nil {
			proxy, _ := ctx.Value(proxyKey).(string)
			pc, err := getPacketConn(ctx, ip, uint16(p), proxy, t.forceHTTP3)
			if err != nil {
				t.mux.Unlock()
				return nil, fmt.Errorf("dial quic earlyConn failed: dial packetconn error: %w, proxy=%s", err, proxy)
			}
			_, t.isUDPConn = pc.(*net.UDPConn)
			t.transport = &quic.Transport{Conn: pc}
			transport = t.transport
		}
		t.mux.Unlock()

		conn, err := transport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
		if err != nil {
			err = fmt.Errorf("dial quic earlyConn failed: %w", err)
		}
		if t.isUDPConn || err == nil {
			return conn, err
		}

		t.mux.Lock()
		t.transport = nil
		t.mux.Unlock()

		_ = transport.Close()
		_ = transport.Conn.Close()
		return nil, err
	}
}

func newHttp3Transport(serverName string, forceHTTP3 bool) *http3Transport {
	h3Transport := &http3Transport{
		forceHTTP3: forceHTTP3,
	}

	dial := h3Transport.makeDialer()

	h3Transport.roundTripper = &http3.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: serverName,
			NextProtos: []string{"dns"},
		},
		QUICConfig: &quic.Config{
			MaxIdleTimeout:        120 * time.Second,
			KeepAlivePeriod:       15 * time.Second,
			HandshakeIdleTimeout:  resolver.DefaultDNSTimeout,
			MaxIncomingStreams:    -1,
			MaxIncomingUniStreams: 1 << 60,
		},
		Dial: dial,
	}

	return h3Transport
}
