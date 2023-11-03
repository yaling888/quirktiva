//go:build linux && !android && !nogvisor

package wireguard

import (
	_ "unsafe"
)

//go:linkname stickyControlSize golang.zx2c4.com/wireguard/conn.stickyControlSize
var stickyControlSize int
