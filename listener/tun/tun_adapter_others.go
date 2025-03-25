//go:build nogvisor || !linux

package tun

import (
	"github.com/yaling888/quirktiva/adapter/inbound"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/ipstack"
)

// New TunAdapter
func New(
	tunConf *C.Tun,
	tcpIn chan<- C.ConnContext,
	udpIn chan<- *inbound.PacketAdapter,
	tunChangeCallback C.TUNChangeCallback,
) (ipstack.Stack, error) {
	return newTunAdapter(tunConf, tcpIn, udpIn, tunChangeCallback)
}
