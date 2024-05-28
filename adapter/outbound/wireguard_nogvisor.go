//go:build nogvisor

package outbound

import (
	"context"
	"fmt"

	"github.com/yaling888/quirktiva/component/dialer"
	C "github.com/yaling888/quirktiva/constant"
)

var _ C.ProxyAdapter = (*WireGuard)(nil)

type WireGuard struct {
	*Base
}

func (w *WireGuard) DialContext(_ context.Context, _ *C.Metadata, _ ...dialer.Option) (C.Conn, error) {
	panic("unimplemented")
}

func (w *WireGuard) UpdateBind() {}

func NewWireGuard(_ WireGuardOption) (*WireGuard, error) {
	return nil, fmt.Errorf("gVisor is not supported on this platform")
}
