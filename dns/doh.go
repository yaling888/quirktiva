package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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
			tr = dc.newTransport(true)
			if t, loaded := dc.transports.Swap(proxy, tr); loaded {
				closeTransport(t)
			}
		}
		return roundTrip(req, tr.(http.RoundTripper))
	}

	return dc.batchRoundTrip(req, proxy)
}

func (dc *dohClient) batchRoundTrip(req *http.Request, proxy string) (*D.Msg, error) {
	ch3 := dc.asyncRoundTripWithNewTransport(req, proxy, true)
	ch := dc.asyncRoundTripWithNewTransport(req, proxy, false)

	select {
	case rs := <-ch3:
		return rs.msg, rs.err
	case rs := <-ch:
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
			newCtx, cancel := context.WithTimeout(newCtx, resolver.DefaultDNSTimeout)
			defer cancel()
			newReq = newReq.WithContext(newCtx)
		}

		tr := dc.newTransport(isH3)
		if proxy != "" && !isH3 {
			tr.(*http.Transport).IdleConnTimeout = 10 * time.Minute
		}

		msg, err := roundTrip(newReq, tr)
		if err == nil && isH3 {
			if t, loaded := dc.transports.Swap(proxy, tr); loaded {
				closeTransport(t)
			}
		} else {
			if isH3 {
				closeTransport(tr)
			} else {
				if _, loaded := dc.transports.LoadOrStore(proxy, tr); loaded {
					closeTransport(tr)
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
			return getTCPConn(ctx, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: dc.host,
			NextProtos: []string{"dns"},
		},
		MaxIdleConnsPerHost: 5,
	}
}

func roundTrip(req *http.Request, transport http.RoundTripper) (*D.Msg, error) {
	client1 := &http.Client{Transport: transport}
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
	roundTripper *http3.RoundTripper
	forceHTTP3   bool

	mux        sync.Mutex
	transports map[string]*quic.Transport
}

func (t *http3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.roundTripper.RoundTrip(req)
}

func (t *http3Transport) Close() error {
	_ = t.roundTripper.Close()
	t.mux.Lock()
	defer t.mux.Unlock()
	for _, tr := range t.transports {
		_ = tr.Close()
		_ = tr.Conn.Close()
	}
	t.transports = nil
	return nil
}

func (t *http3Transport) CloseIdleConnections() {
	t.roundTripper.CloseIdleConnections()
}

func (t *http3Transport) makeDialer() func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
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

		key := addr
		proxy, ok := ctx.Value(proxyKey).(string)
		if ok {
			key += proxy
		}

		t.mux.Lock()
		if t.transports == nil {
			t.transports = make(map[string]*quic.Transport)
		}
		transport := t.transports[key]
		t.mux.Unlock()

		var conn quic.EarlyConnection
		if transport != nil {
			conn, err = transport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
			if err == nil {
				return conn, nil
			}

			t.mux.Lock()
			if t.transports != nil {
				delete(t.transports, key)
			}
			t.mux.Unlock()

			_ = transport.Close()
			_ = transport.Conn.Close()

			if nErr, ok := err.(net.Error); (ok && nErr.Timeout()) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
		}

		pc, err := getPacketConn(ctx, ip, uint16(p), proxy, t.forceHTTP3)
		if err != nil {
			return nil, err
		}

		transport = &quic.Transport{Conn: pc}
		conn, err = transport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
		if err == nil {
			t.mux.Lock()
			if t.transports != nil {
				if tr, exist := t.transports[key]; exist {
					_ = tr.Close()
					_ = tr.Conn.Close()
				}
				t.transports[key] = transport
				t.mux.Unlock()
			} else {
				t.mux.Unlock()
				_ = conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
				_ = transport.Close()
				_ = transport.Conn.Close()
				return nil, net.ErrClosed
			}
		} else {
			_ = transport.Close()
			_ = transport.Conn.Close()
		}

		return conn, err
	}
}

func newHttp3Transport(serverName string, forceHTTP3 bool) *http3Transport {
	h3Transport := &http3Transport{
		forceHTTP3: forceHTTP3,
	}

	dial := h3Transport.makeDialer()

	h3Transport.roundTripper = &http3.RoundTripper{
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
