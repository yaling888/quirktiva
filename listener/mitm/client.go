package mitm

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/yaling888/quirktiva/adapter/inbound"
	N "github.com/yaling888/quirktiva/common/net"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/socks5"
)

func getServerConn(serverConn *N.BufferedConn, request *http.Request, srcAddr net.Addr, originTarget net.Addr, in chan<- C.ConnContext) (*N.BufferedConn, error) {
	if serverConn != nil {
		return serverConn, nil
	}

	address := request.URL.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		port := "80"
		if request.TLS != nil {
			port = "443"
		}
		address = net.JoinHostPort(address, port)
	}

	dstAddr := socks5.ParseAddr(address)
	if dstAddr == nil {
		return nil, socks5.ErrAddressNotSupported
	}

	specialProxy := request.Header.Get("Origin-Request-Special-Proxy")
	request.Header.Del("Origin-Request-Special-Proxy")

	left, right := net.Pipe()

	in <- inbound.NewMitm(dstAddr, srcAddr, originTarget, request.Header.Get("User-Agent"), specialProxy, right)

	if request.TLS != nil {
		tlsConn := tls.Client(left, &tls.Config{
			ServerName: request.TLS.ServerName,
		})

		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}

		serverConn = N.NewBufferedConn(tlsConn)
	} else {
		serverConn = N.NewBufferedConn(left)
	}

	return serverConn, nil
}
