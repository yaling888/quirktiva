package tls

import (
	"context"
	"crypto/tls"
	"net"

	C "github.com/yaling888/quirktiva/constant"
)

func StreamTLSConn(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	tlsConn := tls.Client(conn, tlsConfig)

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	err := tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}
