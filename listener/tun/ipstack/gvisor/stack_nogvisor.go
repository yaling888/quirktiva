//go:build nogvisor

package gvisor

import (
	"fmt"
	"net/netip"

	"github.com/yaling888/quirktiva/adapter/inbound"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/device"
	"github.com/yaling888/quirktiva/listener/tun/ipstack"
)

func New(device.Device, []C.DNSUrl, netip.Prefix, chan<- C.ConnContext, chan<- *inbound.PacketAdapter) (ipstack.Stack, error) {
	return nil, fmt.Errorf("gVisor is not supported on this platform")
}
