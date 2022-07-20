package tun

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/Dreamacro/clash/listener/tun/device/tun/driver"
)

const (
	offset     = 0
	defaultMTU = 0 /* auto */
)

func init() {
	guid, _ := windows.GUIDFromString("{330EAEF8-7578-5DF2-D97B-8DADC0EA85CB}")

	tun.WintunTunnelType = "Clash"
	tun.WintunStaticRequestedGUID = &guid
}

func (t *TUN) LUID() uint64 {
	return t.nt.LUID()
}

func newDevice(name string, mtu int) (nt tun.Device, err error) {
	if err = driver.InitWintun(); err != nil {
		return
	}

	return tun.CreateTUN(name, mtu)
}
