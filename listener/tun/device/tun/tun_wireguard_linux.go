package tun

import (
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))
	offset          = 4 + virtioNetHdrLen /* 4 bytes TUN_PI + virtioNetHdrLen */
	defaultMTU      = 1500
)

// virtioNetHdr is defined in the kernel in include/uapi/linux/virtio_net.h. The
// kernel symbol is virtio_net_hdr.
//
//nolint:unused
type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

func (t *TUN) close() {
	if link, err := netlink.LinkByName(t.name); err == nil {
		_ = netlink.LinkSetDown(link)
		_ = netlink.LinkDel(link)
	}
}

func newDevice(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}
