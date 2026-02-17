package mitm

import (
	"context"
	"net"

	"github.com/yaling888/quirktiva/config"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/http"
	"github.com/yaling888/quirktiva/mitm"
	"github.com/yaling888/quirktiva/tunnel"
)

type Listener struct {
	C.Listener
	proxy  *ReverseProxy
	closed bool
}

// Close implements C.Listener
func (l *Listener) Close() error {
	if l.closed {
		return net.ErrClosed
	}
	l.closed = true
	tunnel.SetMitmOptions(nil, nil)
	err := l.Listener.Close()
	l.proxy.Close()
	return err
}

func New(addr string, in chan<- C.ConnContext) (C.Listener, error) {
	certConfig, err := config.GetCertConfig()
	if err != nil {
		return nil, err
	}

	ctx := context.WithValue(context.Background(), http.MitmContextKey, struct{}{})
	l, err := http.NewWithAuthenticate(ctx, addr, in, true)
	if err != nil {
		return nil, err
	}

	mitmOption := &C.MitmOption{
		ApiHost:    C.MitmApiHost,
		CertConfig: certConfig,
		Handler:    &mitm.RewriteHandler{},
	}

	rp := NewReverseProxy(in, mitmOption)

	ml := &Listener{
		Listener: l,
		proxy:    rp,
	}

	tunnel.SetMitmOptions(rp.ConnIn(), mitmOption.CertConfig.NewTLSConfigForHost)

	return ml, nil
}
