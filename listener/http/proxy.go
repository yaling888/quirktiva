package http

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/adapter/inbound"
	"github.com/yaling888/quirktiva/common/cache"
	N "github.com/yaling888/quirktiva/common/net"
	"github.com/yaling888/quirktiva/component/auth"
	C "github.com/yaling888/quirktiva/constant"
	authStore "github.com/yaling888/quirktiva/listener/auth"
)

func HandleConn(c net.Conn, in chan<- C.ConnContext, cache *cache.LruCache[string, bool], auth auth.Authenticator) {
	client := newClient(c.RemoteAddr(), c.LocalAddr(), in)
	defer client.CloseIdleConnections()

	conn := N.NewBufferedConn(c)

	keepAlive := true
	trusted := cache == nil // disable authenticate if cache is nil

	for keepAlive {
		request, err := ReadRequest(conn.Reader())
		if err != nil {
			break
		}

		request.RemoteAddr = conn.RemoteAddr().String()

		keepAlive = strings.TrimSpace(strings.ToLower(request.Header.Get("Proxy-Connection"))) == "keep-alive"

		var resp *http.Response

		if !trusted {
			resp = Authenticate(request, cache, auth)

			trusted = resp == nil
		}

		if trusted {
			if request.Method == http.MethodConnect {
				// Manual writing to support CONNECT for http 1.0 (workaround for uplay client)
				if _, err = fmt.Fprintf(conn, "HTTP/%d.%d %03d %s\r\n\r\n", request.ProtoMajor, request.ProtoMinor, http.StatusOK, "Connection established"); err != nil {
					break // close connection
				}

				in <- inbound.NewHTTPS(request, conn)

				return // hijack connection
			}

			host := request.Header.Get("Host")
			if host != "" {
				request.Host = host
			}

			request.RequestURI = ""

			if isUpgradeRequest(request) {
				if resp = HandleUpgrade(conn, nil, request, in); resp == nil {
					return // hijack connection
				}
			}

			if resp == nil {
				RemoveHopByHopHeaders(request.Header)
				RemoveExtraHTTPHostPort(request)

				if request.URL.Scheme == "" || request.URL.Host == "" {
					resp = responseWith(request, http.StatusBadRequest)
				} else {
					resp, err = client.Do(request)
					if err != nil {
						resp = responseWith(request, http.StatusBadGateway)
					}
				}
			}

			RemoveHopByHopHeaders(resp.Header)
		}

		if keepAlive {
			resp.Header.Set("Proxy-Connection", "keep-alive")
			resp.Header.Set("Connection", "keep-alive")
			resp.Header.Set("Keep-Alive", "timeout=4")
		}

		resp.Close = !keepAlive

		err = resp.Write(conn)
		if err != nil {
			break // close connection
		}
	}

	_ = conn.Close()
}

func Authenticate(request *http.Request, cache *cache.LruCache[string, bool], auth auth.Authenticator) *http.Response {
	authenticator := auth
	if authenticator == nil {
		authenticator = authStore.Authenticator()
	}
	if authenticator != nil {
		credential := parseBasicProxyAuthorization(request)
		if credential == "" {
			resp := responseWith(request, http.StatusProxyAuthRequired)
			resp.Header.Set("Proxy-Authenticate", "Basic")
			return resp
		}

		authed, exist := cache.Get(credential)
		if !exist {
			user, pass, err := decodeBasicProxyAuthorization(credential)
			authed = err == nil && authenticator.Verify(user, pass)
			cache.Set(credential, authed)
		}
		if !authed {
			log.Info().Str("client", request.RemoteAddr).Msg("[Inbound] server auth failed")

			return responseWith(request, http.StatusForbidden)
		}
	}

	return nil
}

func responseWith(request *http.Request, statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Proto:      request.Proto,
		ProtoMajor: request.ProtoMajor,
		ProtoMinor: request.ProtoMinor,
		Header:     http.Header{},
	}
}
