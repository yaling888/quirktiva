package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/yaling888/quirktiva/common/cache"
	N "github.com/yaling888/quirktiva/common/net"
	"github.com/yaling888/quirktiva/component/auth"
	C "github.com/yaling888/quirktiva/constant"
	H "github.com/yaling888/quirktiva/listener/http"
)

func HandleConn(c net.Conn, opt *C.MitmOption, in chan<- C.ConnContext, cache *cache.LruCache[string, bool], auth auth.Authenticator) {
	var (
		clientIP   = netip.MustParseAddrPort(c.RemoteAddr().String()).Addr()
		sourceAddr net.Addr
		serverConn *N.BufferedConn
		connState  *tls.ConnectionState
	)

	defer func() {
		if serverConn != nil {
			_ = serverConn.Close()
		}
	}()

	conn := N.NewBufferedConn(c)

	trusted := cache == nil // disable authenticate if cache is nil
	if !trusted {
		trusted = clientIP.IsLoopback() || clientIP.IsUnspecified()
	}

readLoop:
	for {
		// use SetReadDeadline instead of Proxy-Connection keep-alive
		if err := conn.SetReadDeadline(time.Now().Add(65 * time.Second)); err != nil {
			break
		}

		request, err := H.ReadRequest(conn.Reader())
		if err != nil {
			break
		}

		var response *http.Response

		session := C.NewMitmSession(conn, request, response)

		sourceAddr = parseSourceAddress(session.Request, conn.RemoteAddr(), sourceAddr)
		session.Request.RemoteAddr = sourceAddr.String()

		if !trusted {
			session.Response = H.Authenticate(session.Request, cache, auth)

			trusted = session.Response == nil
		}

		if trusted {
			if session.Request.Method == http.MethodConnect {
				if session.Request.ProtoMajor > 1 {
					session.Request.ProtoMajor = 1
					session.Request.ProtoMinor = 1
				}

				// Manual writing to support CONNECT for http 1.0 (workaround for uplay client)
				if _, err = fmt.Fprintf(session.Conn, "HTTP/%d.%d %03d %s\r\n\r\n", session.Request.ProtoMajor, session.Request.ProtoMinor, http.StatusOK, "Connection established"); err != nil {
					handleError(opt, session, err)
					break // close connection
				}

				if strings.HasSuffix(session.Request.URL.Host, ":80") {
					goto readLoop
				}

				b, err1 := conn.Peek(1)
				if err1 != nil {
					handleError(opt, session, err1)
					break // close connection
				}

				// TLS handshake.
				if b[0] == 0x16 {
					tlsConn := tls.Server(conn, opt.CertConfig.NewTLSConfigForHost(session.Request.URL.Hostname()))

					ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
					// handshake with the local client
					if err = tlsConn.HandshakeContext(ctx); err != nil {
						cancel()
						session.Response = session.NewErrorResponse(fmt.Errorf("handshake failed: %w", err))
						_ = writeResponse(session, false)
						break // close connection
					}
					cancel()

					cs := tlsConn.ConnectionState()
					connState = &cs

					conn = N.NewBufferedConn(tlsConn)
				}

				if strings.HasSuffix(session.Request.URL.Host, ":443") {
					goto readLoop
				}

				if conn.SetReadDeadline(time.Now().Add(time.Second)) != nil {
					break
				}

				buf, err2 := conn.Peek(7)
				if err2 != nil {
					if err2 != bufio.ErrBufferFull && !os.IsTimeout(err2) {
						handleError(opt, session, err2)
						break // close connection
					}
				}

				// others protocol over tcp
				if !isHTTPTraffic(buf) {
					if connState != nil {
						session.Request.TLS = connState
					}

					serverConn, err = getServerConn(serverConn, session.Request, sourceAddr, conn.LocalAddr(), in)
					if err != nil {
						break
					}

					if conn.SetReadDeadline(time.Time{}) != nil {
						break
					}

					N.Relay(serverConn, conn)
					return // hijack connection
				}

				goto readLoop
			}

			prepareRequest(connState, session.Request)

			// hijack api
			if session.Request.URL.Hostname() == opt.ApiHost {
				if err = handleApiRequest(session, opt); err != nil {
					handleError(opt, session, err)
				}
				break
			}

			// forward websocket
			if isWebsocketRequest(request) {
				serverConn, err = getServerConn(serverConn, session.Request, sourceAddr, conn.LocalAddr(), in)
				if err != nil {
					break
				}

				session.Request.RequestURI = ""
				if session.Response = H.HandleUpgrade(conn, serverConn, request, in); session.Response == nil {
					return // hijack connection
				}
			}

			if session.Response == nil {
				H.RemoveHopByHopHeaders(session.Request.Header)
				H.RemoveExtraHTTPHostPort(session.Request)

				// hijack custom request and write back custom response if necessary
				newReq, newRes := opt.Handler.HandleRequest(session)
				if newReq != nil {
					session.Request = newReq
				}
				if newRes != nil {
					session.Response = newRes

					if err = writeResponse(session, false); err != nil {
						handleError(opt, session, err)
						break
					}
					continue
				}

				session.Request.RequestURI = ""

				if session.Request.URL.Host == "" {
					session.Response = session.NewErrorResponse(C.ErrInvalidURL)
				} else {
					serverConn, err = getServerConn(serverConn, session.Request, sourceAddr, conn.LocalAddr(), in)
					if err != nil {
						break
					}

					// send the request to remote server
					err = session.Request.Write(serverConn)
					if err != nil {
						break
					}

					session.Response, err = http.ReadResponse(serverConn.Reader(), request)
					if err != nil {
						break
					}
				}
			}
		}

		if err = writeResponseWithHandler(session, opt); err != nil {
			handleError(opt, session, err)
			break // close connection
		}
	}

	_ = conn.Close()
}

func writeResponseWithHandler(session *C.MitmSession, opt *C.MitmOption) error {
	res := opt.Handler.HandleResponse(session)
	if res != nil {
		session.Response = res
	}

	return writeResponse(session, true)
}

func writeResponse(session *C.MitmSession, keepAlive bool) error {
	H.RemoveHopByHopHeaders(session.Response.Header)

	if keepAlive {
		session.Response.Header.Set("Connection", "keep-alive")
		session.Response.Header.Set("Keep-Alive", "timeout=60")
	}

	return session.WriteResponse()
}

func handleApiRequest(session *C.MitmSession, opt *C.MitmOption) error {
	if opt.CertConfig != nil && strings.ToLower(session.Request.URL.Path) == "/cert.crt" {
		b := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: opt.CertConfig.GetRootCA().Raw,
		})

		session.Response = session.NewResponse(http.StatusOK, bytes.NewReader(b))

		session.Response.Close = true
		session.Response.Header.Set("Content-Type", "application/x-x509-ca-cert")
		session.Response.ContentLength = int64(len(b))

		return session.WriteResponse()
	}

	b := `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Clash MITM Proxy Services - 404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL %s was not found on this server.</p>
</body></html>
`

	if opt.Handler.HandleApiRequest(session) {
		return nil
	}

	b = fmt.Sprintf(b, session.Request.URL.Path)

	session.Response = session.NewResponse(http.StatusNotFound, bytes.NewReader([]byte(b)))
	session.Response.Close = true
	session.Response.Header.Set("Content-Type", "text/html;charset=utf-8")
	session.Response.ContentLength = int64(len(b))

	return session.WriteResponse()
}

func handleError(opt *C.MitmOption, session *C.MitmSession, err error) {
	if session.Response != nil {
		defer func() {
			_, _ = io.Copy(io.Discard, session.Response.Body)
			_ = session.Response.Body.Close()
		}()
	}
	opt.Handler.HandleError(session, err)
}

func prepareRequest(connState *tls.ConnectionState, request *http.Request) {
	host := request.Header.Get("Host")
	if host != "" {
		request.Host = host
	}

	if request.URL.Host == "" {
		request.URL.Host = request.Host
	}

	if request.URL.Scheme == "" {
		request.URL.Scheme = "http"
	}

	if connState != nil {
		request.TLS = connState
		request.URL.Scheme = "https"
	}

	if request.Header.Get("Accept-Encoding") != "" {
		request.Header.Set("Accept-Encoding", "gzip")
	}
}

func parseSourceAddress(req *http.Request, connSource, source net.Addr) net.Addr {
	if source != nil {
		return source
	}

	sourceAddress := req.Header.Get("Origin-Request-Source-Address")
	if sourceAddress == "" {
		return connSource
	}

	req.Header.Del("Origin-Request-Source-Address")

	addrPort, err := netip.ParseAddrPort(sourceAddress)
	if err != nil {
		return connSource
	}

	return net.TCPAddrFromAddrPort(addrPort)
}

func isWebsocketRequest(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Connection"), "Upgrade") && strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
}

func isHTTPTraffic(buf []byte) bool {
	method, _, _ := strings.Cut(string(buf), " ")
	return validMethod(method)
}

func validMethod(method string) bool {
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

func isNotToken(r rune) bool {
	return !httpguts.IsTokenRune(r)
}
