//go:build !nogvisor

package tun

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/yaling888/quirktiva/listener/tun/device/iobased"
)

var _ stack.LinkEndpoint = (*TUN)(nil)

type TUN struct {
	*iobased.Endpoint

	nt     tun.Device
	mtu    uint32
	name   string
	offset int
}

func (t *TUN) Close2() error {
	t.close()

	defer func(ep *iobased.Endpoint) {
		if ep != nil {
			ep.Close()
		}
	}(t.Endpoint)
	return t.nt.Close()
}

func (t *TUN) Close() {
	_ = t.Close2()
}

func (t *TUN) UseEndpoint() error {
	ep, err := iobased.New(t, t.mtu, t.offset)
	if err != nil {
		return fmt.Errorf("create endpoint: %w", err)
	}
	t.Endpoint = ep
	return nil
}
