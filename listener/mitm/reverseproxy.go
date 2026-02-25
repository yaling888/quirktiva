package mitm

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"html"
	stdLog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/common/cert"
	"github.com/yaling888/quirktiva/common/pool"
	"github.com/yaling888/quirktiva/constant"
	context1 "github.com/yaling888/quirktiva/context"
)

var (
	inConnCtxMap = sync.Map{}
	outConnMap   = sync.Map{}

	connKeyContextKey = &contextKey{"connection-key"}
	connCtxContextKey = &contextKey{"connection-context"}

	errNoConnCtxFound = net.InvalidAddrError("no connection context found")
	errNoConnKeyFound = net.InvalidAddrError("no connection key found")
)

type contextKey struct {
	name string
}

type mitmConnectionKey struct {
	ptrAddr string
}

func getMitmConnectionKey(c net.Conn) mitmConnectionKey {
	return mitmConnectionKey{
		ptrAddr: fmt.Sprintf("%p:%v", c, c.RemoteAddr()),
	}
}

type connCtx struct {
	mux      sync.Mutex
	metadata *constant.Metadata
	close    func() error
	err      error
}

func (c *connCtx) cancelCause(err error) {
	_ = c.close()
	c.err = err
}

type mitmServe struct {
	proxy  *httputil.ReverseProxy
	option *constant.MitmOption
}

func (ms *mitmServe) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	cCtx, ok := ctx.Value(connCtxContextKey).(*connCtx)
	if !ok {
		log.Error().Err(errNoConnCtxFound).Msg("[MITM] serve http")
		rw.WriteHeader(http.StatusBadGateway)
		return
	}

	fixRequestURL(req, cCtx)

	handleUserAgent(req, cCtx)

	if handleApiRequest(rw, req, ms.option.CertConfig) {
		return
	}

	if ms.option.Handler.HandleRequest(rw, req) {
		return
	}

	ms.proxy.ServeHTTP(rw, req)
}

type ReverseProxy struct {
	*reverseProxy
}

type reverseProxy struct {
	listener *mitmListener
	server   *http.Server
}

func (rp *reverseProxy) ConnIn() chan<- constant.ConnContext {
	return rp.listener.ConnIn()
}

func (rp *reverseProxy) Close() {
	rp.stop()
}

func (rp *reverseProxy) stop() {
	_ = rp.server.Close()
	cleanup()
}

var mitmErrLog = stdLog.New(stdLog.Writer(), "mitm: ", 0)

func NewReverseProxy(tcpIn chan<- constant.ConnContext, option *constant.MitmOption) *ReverseProxy {
	p := &httputil.ReverseProxy{
		BufferPool:     &bufferPool{},
		ErrorLog:       mitmErrLog,
		Transport:      newRoundTripper(tcpIn),
		ModifyResponse: option.Handler.HandleResponse,
		Rewrite: func(r *httputil.ProxyRequest) { // do not use r.SetXForwarded()
			// use the client original request Accept-Encoding, save the network bandwidth.
			if acceptEncoding := strings.ToLower(r.In.Header.Get("Accept-Encoding")); acceptEncoding != "" {
				enc := slices.DeleteFunc(strings.Split(acceptEncoding, ","), func(s string) bool {
					s, _ = strings.CutPrefix(s, " ")
					return s != "gzip" && s != "deflate" && s != "br" && s != "zstd"
				})
				if len(enc) != 0 {
					r.Out.Header.Set("Accept-Encoding", strings.Join(enc, ","))
				} else {
					r.Out.Header.Del("Accept-Encoding")
				}
			}
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			log.Warn().Err(err).Msg("[MITM] http: reverse proxy")
			if cCtx, ok := req.Context().Value(connCtxContextKey).(*connCtx); ok {
				cCtx.cancelCause(err)
			} else {
				rw.WriteHeader(http.StatusBadGateway)
			}
		},
	}

	h := &mitmServe{
		proxy:  p,
		option: option,
	}

	s := &http.Server{
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			connKey := getMitmConnectionKey(c)
			ctx = context.WithValue(ctx, connKeyContextKey, connKey)
			if value, ok := inConnCtxMap.Load(connKey); ok {
				connContext := value.(*connCtx)
				return context.WithValue(ctx, connCtxContextKey, connContext)
			}
			return ctx
		},
		ConnState: func(c net.Conn, state http.ConnState) {
			switch state {
			case http.StateHijacked:
				connKey := getMitmConnectionKey(c)
				inConnCtxMap.Delete(connKey)
				outConnMap.Delete(connKey)
			case http.StateClosed:
				connKey := getMitmConnectionKey(c)
				inConnCtxMap.Delete(connKey)
				if cc, loaded := outConnMap.LoadAndDelete(connKey); loaded {
					_ = cc.(*http.ClientConn).Close()
				}
			default:
			}
		},
		DisableGeneralOptionsHandler: true, // passes "OPTIONS *" requests to the remote server
		IdleTimeout:                  90 * time.Second,
		ErrorLog:                     mitmErrLog,
		Handler:                      h,
	}

	l := newMitmListener()

	rp := &ReverseProxy{
		reverseProxy: &reverseProxy{
			listener: l,
			server:   s,
		},
	}

	runtime.SetFinalizer(rp, (*ReverseProxy).stop)

	go func() {
		if err := s.Serve(l); err != http.ErrServerClosed {
			log.Error().Err(err).Msg("[MITM] failed to serve mitm server")
		}
	}()
	return rp
}

type roundTripper struct {
	transport *http.Transport
}

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	cCtx, ok := ctx.Value(connCtxContextKey).(*connCtx)
	if !ok {
		return nil, errNoConnCtxFound
	}

	connKey, ok := ctx.Value(connKeyContextKey).(mitmConnectionKey)
	if !ok {
		return nil, errNoConnKeyFound
	}

	// one incoming connection allow to create only one outgoing connection
	cCtx.mux.Lock()
	defer cCtx.mux.Unlock()

	if c, loaded := outConnMap.Load(connKey); loaded {
		cc := c.(*http.ClientConn)
		if cc.Available() > 0 {
			return cc.RoundTrip(req)
		}
	}

	hostPort := req.URL.Host // can use a fake hostPort. the dial function use the metadata to pipe the connection
	if !hasPort(hostPort) {
		port := schemePort(req.URL.Scheme)
		hostPort = net.JoinHostPort(hostPort, port)
	}

	cc, err := r.transport.NewClientConn(ctx, req.URL.Scheme, hostPort) // bug inside, must have a port
	if err != nil {
		return nil, err
	}
	if c, loaded := outConnMap.Swap(connKey, cc); loaded && c != cc {
		_ = c.(*http.ClientConn).Close()
	}

	cc.SetStateHook(func(cc *http.ClientConn) {
		if cc.Err() != nil { // closed
			cCtx.cancelCause(cc.Err())
			if c, loaded := outConnMap.LoadAndDelete(connKey); loaded {
				_ = c.(*http.ClientConn).Close()
			}
		}
	})
	return cc.RoundTrip(req)
}

func newRoundTripper(tcpIn chan<- constant.ConnContext) http.RoundTripper {
	dialFn := func(ctx context.Context, _ string, _ string, isTLS bool) (net.Conn, error) {
		if cCtx, ok := ctx.Value(connCtxContextKey).(*connCtx); ok {
			metadata := new(constant.Metadata)
			*metadata = *cCtx.metadata

			left, right := net.Pipe()
			tcpIn <- context1.NewConnContext(right, metadata)

			if isTLS {
				tlsConfig := &tls.Config{
					ServerName: metadata.String(),
					NextProtos: []string{"h2", "http/1.1", "http/1.0"},
				}
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, constant.DefaultTCPTimeout)
				defer cancel()
				tlsConn := tls.Client(left, tlsConfig)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					return nil, fmt.Errorf("failed to tls handshake to server %s: %w", tlsConfig.ServerName, err)
				}
				return tlsConn, nil
			}
			return left, nil
		}
		return nil, errNoConnCtxFound
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return dialFn(ctx, network, addr, false)
		},
		DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return dialFn(ctx, network, addr, true)
		},
		ForceAttemptHTTP2:   true,
		DisableCompression:  true, // disable response body automatically uncompressed
		DisableKeepAlives:   false,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		// MaxConnsPerHost:     1, // this will cause panic
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &roundTripper{
		transport: transport,
	}
}

type bufferPool struct{}

func (b *bufferPool) Get() []byte {
	return *pool.GetNetBuf()
}

func (b *bufferPool) Put(p []byte) {
	pool.PutNetBuf(&p)
}

func hasPort(host string) bool {
	if i := strings.LastIndex(host, ":"); i > -1 && i > strings.LastIndex(host, "]") {
		return true
	}
	return false
}

func schemePort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func fixRequestURL(req *http.Request, cCtx *connCtx) {
	if req.URL.Scheme == "" {
		if req.TLS != nil {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}
	}
	if req.URL.Host == "" {
		if req.ProtoMajor > 1 && req.Host != "" && !hasPort(req.Host) {
			req.URL.Host = req.Host
		} else {
			req.URL.Host = cCtx.metadata.String()
		}
	} else if hasPort(req.URL.Host) {
		req.URL.Host = cCtx.metadata.String()
	}
}

func handleApiRequest(rw http.ResponseWriter, req *http.Request, certCfg *cert.Config) bool {
	if req.URL.Hostname() != constant.MitmApiHost {
		return false
	}

	if strings.ToLower(req.URL.Path) == "/cert.crt" {
		b := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certCfg.GetRootCA().Raw,
		})

		rw.Header().Set("Content-Type", "application/x-x509-ca-cert")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(b)
		return true
	}

	b := `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Clash MITM Proxy Services - 404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL %s was not found on this server.</p>
</body></html>
`

	rw.Header().Set("Content-Type", "text/html; charset=UTF-8")
	rw.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprintf(rw, b, html.EscapeString(req.URL.Path))
	return true
}

func handleUserAgent(req *http.Request, cCtx *connCtx) {
	cCtx.metadata.UserAgent = req.Header.Get("User-Agent")
}

func cleanup() {
	inConnCtxMap.Range(func(key, value any) bool {
		value.(*connCtx).cancelCause(net.ErrClosed)
		return true
	})
	inConnCtxMap.Clear()
	outConnMap.Range(func(key, value any) bool {
		_ = value.(*http.ClientConn).Close()
		return true
	})
	outConnMap.Clear()
}
