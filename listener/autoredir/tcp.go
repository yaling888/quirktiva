package autoredir

import (
	"net"
	"net/netip"

	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/adapter/inbound"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/socks5"
)

type Listener struct {
	listener   net.Listener
	addr       string
	closed     bool
	lookupFunc func(netip.AddrPort) (socks5.Addr, error)
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

func (l *Listener) TCPAddr() netip.AddrPort {
	return l.listener.Addr().(*net.TCPAddr).AddrPort()
}

func (l *Listener) SetLookupFunc(lookupFunc func(netip.AddrPort) (socks5.Addr, error)) {
	l.lookupFunc = lookupFunc
}

func (l *Listener) handleRedir(conn net.Conn, in chan<- C.ConnContext) {
	if l.lookupFunc == nil {
		log.Error().Msg("[Auto Redirect] lookup function is nil")
		return
	}

	target, err := l.lookupFunc(conn.RemoteAddr().(*net.TCPAddr).AddrPort())
	if err != nil {
		log.Warn().Err(err).Msg("[Auto Redirect]")
		_ = conn.Close()
		return
	}

	_ = conn.(*net.TCPConn).SetKeepAlive(true)

	in <- inbound.NewSocket(target, conn, C.REDIR)
}

func New(addr string, in chan<- C.ConnContext) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	al := &Listener{
		listener: l,
		addr:     addr,
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if al.closed {
					break
				}
				continue
			}
			go al.handleRedir(c, in)
		}
	}()

	return al, nil
}
