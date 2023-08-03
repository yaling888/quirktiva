package mitm

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phuslu/log"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/common/cert"
	C "github.com/Dreamacro/clash/constant"
	rewrites "github.com/Dreamacro/clash/rewrite"
	"github.com/Dreamacro/clash/tunnel"
)

var (
	mitmOption *C.MitmOption
	optionOnce sync.Once
	proxyDone  uint32
)

type Listener struct {
	listener net.Listener
	addr     string
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
		atomic.StoreUint32(&proxyDone, 0)
	}
	l.closed = true
	return l.listener.Close()
}

// New the MITM proxy actually is a type of HTTP proxy
func New(addr string, in chan<- C.ConnContext) (C.Listener, error) {
	var err error
	optionOnce.Do(func() {
		mitmOption, err = initOption()
	})
	if err != nil {
		return nil, err
	}

	ml, err := NewWithAuthenticate(addr, mitmOption, in, true)
	if err != nil {
		return nil, err
	}

	if atomic.LoadUint32(&proxyDone) == 0 {
		ml.asProxy = true
		atomic.StoreUint32(&proxyDone, 1)
		tunnel.SetMitmOutbound(outbound.NewMitm(ml.Address()))
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
			go HandleConn(conn, option, in, c)
		}
	}()

	return ml, nil
}

func initOption() (*C.MitmOption, error) {
	if err := initCert(); err != nil {
		return nil, err
	}

	rootCACert, err := tls.LoadX509KeyPair(C.Path.RootCA(), C.Path.CAKey())
	if err != nil {
		return nil, err
	}

	privateKey := rootCACert.PrivateKey.(*rsa.PrivateKey)

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

	certOption.SetValidity(time.Hour * 24 * 365 * 2) // 2 years
	certOption.SetOrganization("Clash ManInTheMiddle Proxy Services")

	option := &C.MitmOption{
		ApiHost:    "mitm.clash",
		CertConfig: certOption,
		Handler:    &rewrites.RewriteHandler{},
	}

	return option, nil
}

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
