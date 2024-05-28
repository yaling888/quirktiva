package redir

import (
	"net"

	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/adapter/inbound"
	C "github.com/yaling888/quirktiva/constant"
)

type Listener struct {
	listener net.Listener
	addr     string
	closed   bool
}

// RawAddress implements C.Listener
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *Listener) Address() string {
	return l.listener.Addr().String()
}

// Close implements C.Listener
func (l *Listener) Close() error {
	l.closed = true
	return l.listener.Close()
}

func New(addr string, in chan<- C.ConnContext) (C.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	rl := &Listener{
		listener: l,
		addr:     addr,
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if rl.closed {
					break
				}
				continue
			}
			go handleRedir(c, in)
		}
	}()

	return rl, nil
}

func handleRedir(conn net.Conn, in chan<- C.ConnContext) {
	target, err := parserPacket(conn)
	if err != nil {
		_ = conn.Close()
		log.Warn().Err(err).Msg("[Redir] handle redirect")
		return
	}
	_ = conn.(*net.TCPConn).SetKeepAlive(true)
	in <- inbound.NewSocket(target, conn, C.REDIR)
}
