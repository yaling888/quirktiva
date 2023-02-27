package tun

import (
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	offset     = 4 /* 4 bytes TUN_PI */
	defaultMTU = 1500
)

func (t *TUN) close() {
	if link, err := netlink.LinkByName(t.name); err == nil {
		_ = netlink.LinkSetDown(link)
		_ = netlink.LinkDel(link)
	}
}

func newDevice(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}
