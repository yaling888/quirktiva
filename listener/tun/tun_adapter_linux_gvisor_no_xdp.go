//go:build !nogvisor && linux && !amd64 && !arm64

package tun

import (
	"errors"

	"github.com/yaling888/quirktiva/adapter/inbound"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/ipstack"
)

func newXDPAdapter(_ *C.Tun, _ chan<- C.ConnContext, _ chan<- *inbound.PacketAdapter) (ipstack.Stack, error) {
	return nil, errors.New("XDP stack only supports linux amd64 and arm64 with gVisor")
}
