package autoredir

import (
	"net"
	"net/netip"

	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/adapter/inbound"
	C "github.com/yaling888/quirktiva/constant"
)

type Listener struct {
	listener   net.Listener
	addr       string
	closed     bool
	lookupFunc func(netip.AddrPort) (netip.AddrPort, error)
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

func (l *Listener) handleRedir(conn net.Conn, in chan<- C.ConnContext) {
	src := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	dst, err := l.lookupFunc(src)
	if err != nil {
		log.Warn().Err(err).Msg("[Auto Redirect] handle tcp")
		_ = conn.Close()
		return
	}

	if dst.Addr().Is4In6() {
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	}

	_ = conn.(*net.TCPConn).SetKeepAlive(true)

	in <- inbound.NewSocketBy(conn, src, dst, C.REDIR)
}

func New(addr string, in chan<- C.ConnContext, lookupFunc func(netip.AddrPort) (netip.AddrPort, error)) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	al := &Listener{
		listener:   l,
		addr:       addr,
		lookupFunc: lookupFunc,
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
