//go:build nohy2

package outbound

import (
	"context"
	"errors"

	"github.com/yaling888/quirktiva/component/dialer"
	C "github.com/yaling888/quirktiva/constant"
)

type Hysteria2Option struct {
	Name             string `proxy:"name"`
	SkipCertVerify   bool   `proxy:"skip-cert-verify,omitempty"`
	UDP              bool   `proxy:"udp,omitempty"`
	RemoteDnsResolve bool   `proxy:"remote-dns-resolve,omitempty"`
}

var _ C.ProxyAdapter = (*Hysteria2)(nil)

type Hysteria2 struct {
	*Base
}

func (h *Hysteria2) DialContext(_ context.Context, _ *C.Metadata, _ ...dialer.Option) (C.Conn, error) {
	panic("unimplemented")
}

func NewHysteria2(_ Hysteria2Option) (*Hysteria2, error) {
	return nil, errors.New("hysteria2 is not supported for this release")
}
