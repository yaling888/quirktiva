//go:build nogvisor

package tun

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

type TUN struct {
	nt     tun.Device
	mtu    uint32
	name   string
	offset int
}

func (t *TUN) Close() error {
	t.close()
	return t.nt.Close()
}

func (t *TUN) UseEndpoint() error {
	return fmt.Errorf("gVisor is not supported on this platform")
}
