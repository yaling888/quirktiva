package http

import (
	"net"

	"github.com/yaling888/quirktiva/common/cache"
	"github.com/yaling888/quirktiva/component/auth"
	C "github.com/yaling888/quirktiva/constant"
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
	return NewWithAuthenticate(addr, in, true)
}

func NewWithAuthenticate(addr string, in chan<- C.ConnContext, authenticate bool) (C.Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	var c *cache.LruCache[string, bool]
	if authenticate {
		c = cache.New[string, bool](cache.WithAge[string, bool](30))
	}

	hl := &Listener{
		listener: l,
		addr:     addr,
	}
	go func() {
		for {
			conn, err := hl.listener.Accept()
			if err != nil {
				if hl.closed {
					break
				}
				continue
			}
			go HandleConn(conn, in, c, hl.auth)
		}
	}()

	return hl, nil
}
