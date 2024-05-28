package socks

import (
	"io"
	"net"

	"github.com/yaling888/quirktiva/adapter/inbound"
	N "github.com/yaling888/quirktiva/common/net"
	"github.com/yaling888/quirktiva/component/auth"
	C "github.com/yaling888/quirktiva/constant"
	authStore "github.com/yaling888/quirktiva/listener/auth"
	"github.com/yaling888/quirktiva/transport/socks4"
	"github.com/yaling888/quirktiva/transport/socks5"
)

type Listener struct {
	listener net.Listener
	addr     string
	auth     auth.Authenticator
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

// SetAuthenticator implements C.AuthenticatorListener
func (l *Listener) SetAuthenticator(users []auth.AuthUser) {
	l.auth = auth.NewAuthenticator(users)
}

func New(addr string, in chan<- C.ConnContext) (C.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	sl := &Listener{
		listener: l,
		addr:     addr,
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			go handleSocks(c, in, sl.auth)
		}
	}()

	return sl, nil
}

func New4(addr string, in chan<- C.ConnContext) (C.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	sl := &Listener{
		listener: l,
		addr:     addr,
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			_ = c.(*net.TCPConn).SetKeepAlive(true)
			go HandleSocks4(c, in, sl.auth)
		}
	}()

	return sl, nil
}

func New5(addr string, in chan<- C.ConnContext) (C.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	sl := &Listener{
		listener: l,
		addr:     addr,
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			_ = c.(*net.TCPConn).SetKeepAlive(true)
			go HandleSocks5(c, in, sl.auth)
		}
	}()

	return sl, nil
}

func handleSocks(conn net.Conn, in chan<- C.ConnContext, auth auth.Authenticator) {
	_ = conn.(*net.TCPConn).SetKeepAlive(true)
	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		_ = conn.Close()
		return
	}

	switch head[0] {
	case socks4.Version:
		HandleSocks4(bufConn, in, auth)
	case socks5.Version:
		HandleSocks5(bufConn, in, auth)
	default:
		_ = conn.Close()
	}
}

func HandleSocks4(conn net.Conn, in chan<- C.ConnContext, auth auth.Authenticator) {
	authenticator := auth
	if authenticator == nil {
		authenticator = authStore.Authenticator()
	}
	addr, _, err := socks4.ServerHandshake(conn, authenticator)
	if err != nil {
		_ = conn.Close()
		return
	}
	in <- inbound.NewSocket(socks5.ParseAddr(addr), conn, C.SOCKS4)
}

func HandleSocks5(conn net.Conn, in chan<- C.ConnContext, auth auth.Authenticator) {
	authenticator := auth
	if authenticator == nil {
		authenticator = authStore.Authenticator()
	}
	target, command, err := socks5.ServerHandshake(conn, authenticator)
	if err != nil {
		_ = conn.Close()
		return
	}
	if command == socks5.CmdUDPAssociate {
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
		return
	}
	in <- inbound.NewSocket(target, conn, C.SOCKS5)
}
