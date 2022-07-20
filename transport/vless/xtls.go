package vless

import (
	"context"
	"net"

	xtls "github.com/xtls/go"

	C "github.com/Dreamacro/clash/constant"
)

type XTLSConfig struct {
	Host           string
	SkipCertVerify bool
	NextProtos     []string
}

func StreamXTLSConn(conn net.Conn, cfg *XTLSConfig) (net.Conn, error) {
	xtlsConfig := &xtls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipCertVerify,
		NextProtos:         cfg.NextProtos,
	}

	xtlsConn := xtls.Client(conn, xtlsConfig)

	// fix xtls handshake not timeout
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	err := xtlsConn.HandshakeContext(ctx)
	return xtlsConn, err
}
