package mitm

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"sync"
	"time"

	"github.com/phuslu/log"
	"go.uber.org/atomic"

	"github.com/yaling888/quirktiva/adapter/outbound"
	"github.com/yaling888/quirktiva/common/cache"
	"github.com/yaling888/quirktiva/common/cert"
	"github.com/yaling888/quirktiva/component/auth"
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
	mitmOption, err := initOption()
	if err != nil {
		return nil, err
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

var initOption = sync.OnceValues(func() (*C.MitmOption, error) {
	if err := initCert(); err != nil {
		return nil, err
	}

	rootCACert, err := tls.LoadX509KeyPair(C.Path.RootCA(), C.Path.CAKey())
	if err != nil {
		return nil, err
	}

	privateKey, ok := rootCACert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, rsa.ErrVerification
	}

	x509c, err := x509.ParseCertificate(rootCACert.Certificate[0])
	if err != nil {
		return nil, err
	}

	certOption, err := cert.NewConfig(
		x509c,
		privateKey,
	)
	if err != nil {
		return nil, err
	}

	certOption.SetValidity(time.Hour * 24 * 365) // 1 years

	option := &C.MitmOption{
		ApiHost:    "mitm.clash",
		CertConfig: certOption,
		Handler:    &mitm.RewriteHandler{},
	}

	return option, nil
})

func initCert() error {
	if _, err := os.Stat(C.Path.RootCA()); os.IsNotExist(err) {
		log.Info().Msg("[Config] can't find mitm_ca.crt, start generate")
		err = cert.GenerateAndSave(C.Path.RootCA(), C.Path.CAKey())
		if err != nil {
			return err
		}
		log.Info().Msg("[Config] generated CA private key and CA certificate")
	}

	return nil
}
