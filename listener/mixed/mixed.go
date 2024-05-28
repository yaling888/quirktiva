package mixed

import (
	"net"

	"github.com/yaling888/quirktiva/common/cache"
	N "github.com/yaling888/quirktiva/common/net"
	"github.com/yaling888/quirktiva/component/auth"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/http"
	"github.com/yaling888/quirktiva/listener/socks"
	"github.com/yaling888/quirktiva/transport/socks4"
	"github.com/yaling888/quirktiva/transport/socks5"
)

type Listener struct {
	listener net.Listener
	addr     string
	cache    *cache.LruCache[string, bool]
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

	ml := &Listener{
		listener: l,
		addr:     addr,
		cache:    cache.New[string, bool](cache.WithAge[string, bool](30)),
	}
	go func() {
		for {
			c, err := ml.listener.Accept()
			if err != nil {
				if ml.closed {
					break
				}
				continue
			}
			go handleConn(c, in, ml.cache, ml.auth)
		}
	}()

	return ml, nil
}

func handleConn(conn net.Conn, in chan<- C.ConnContext, cache *cache.LruCache[string, bool], auth auth.Authenticator) {
	_ = conn.(*net.TCPConn).SetKeepAlive(true)

	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		return
	}

	switch head[0] {
	case socks4.Version:
		socks.HandleSocks4(bufConn, in, auth)
	case socks5.Version:
		socks.HandleSocks5(bufConn, in, auth)
	default:
		http.HandleConn(bufConn, in, cache, auth)
	}
}
