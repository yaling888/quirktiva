package mitm

import (
	"net"

	"go.uber.org/atomic"

	"github.com/yaling888/quirktiva/adapter/outbound"
	"github.com/yaling888/quirktiva/common/cache"
	"github.com/yaling888/quirktiva/component/auth"
	"github.com/yaling888/quirktiva/config"
	C "github.com/yaling888/quirktiva/constant"
	authStore "github.com/yaling888/quirktiva/listener/auth"
	"github.com/yaling888/quirktiva/mitm"
	"github.com/yaling888/quirktiva/tunnel"
)

var proxyDone = atomic.NewUint32(0)

type Listener struct {
	listener net.Listener
	addr     string
	auth     auth.Authenticator
	closed   bool
	asProxy  bool
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
	if l.asProxy {
		l.asProxy = false
		tunnel.SetMitmOutbound(nil)
		proxyDone.Store(0)
	}
	l.closed = true
	return l.listener.Close()
}

// SetAuthenticator implements C.AuthenticatorListener
func (l *Listener) SetAuthenticator(users []auth.AuthUser) {
	l.auth = auth.NewAuthenticator(users)
}

func New(addr string, in chan<- C.ConnContext) (C.Listener, error) {
	certConfig, err := config.GetCertConfig()
	if err != nil {
		return nil, err
	}

	mitmOption := &C.MitmOption{
		ApiHost:    C.MitmApiHost,
		CertConfig: certConfig,
		Handler:    &mitm.RewriteHandler{},
	}

	ml, err := NewWithAuthenticate(addr, mitmOption, in, true)
	if err != nil {
		return nil, err
	}

	if proxyDone.Load() == 0 {
		ml.asProxy = true
		proxyDone.Store(1)
		auths := ml.auth
		if auths == nil {
			auths = authStore.Authenticator()
		}
		tunnel.SetMitmOutbound(outbound.NewMitm(ml.Address(), auths))
	}

	return ml, nil
}

func NewWithAuthenticate(addr string, option *C.MitmOption, in chan<- C.ConnContext, authenticate bool) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	var c *cache.LruCache[string, bool]
	if authenticate {
		c = cache.New[string, bool](cache.WithAge[string, bool](90))
	}

	ml := &Listener{
		listener: l,
		addr:     addr,
	}
	go func() {
		for {
			conn, err1 := ml.listener.Accept()
			if err1 != nil {
				if ml.closed {
					break
				}
				continue
			}
			go HandleConn(conn, option, in, c, ml.auth)
		}
	}()

	return ml, nil
}
