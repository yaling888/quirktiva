package net

import (
	"io"
	"net"
	"time"

	"github.com/yaling888/quirktiva/common/pool"
)

// Relay copies between left and right bidirectionally.
func Relay(leftConn, rightConn net.Conn) {
	ch := make(chan error)

	tcpKeepAlive(leftConn)
	tcpKeepAlive(rightConn)

	go func() {
		bufP := pool.GetNetBuf()
		defer pool.PutNetBuf(bufP)
		_, err := io.CopyBuffer(WriteOnlyWriter{Writer: leftConn}, ReadOnlyReader{Reader: rightConn}, *bufP)
		_ = leftConn.SetReadDeadline(time.Now())
		ch <- err
	}()

	bufP := pool.GetNetBuf()
	defer pool.PutNetBuf(bufP)
	_, _ = io.CopyBuffer(WriteOnlyWriter{Writer: rightConn}, ReadOnlyReader{Reader: leftConn}, *bufP)
	_ = rightConn.SetReadDeadline(time.Now())
	<-ch
}

func tcpKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
	}
}
