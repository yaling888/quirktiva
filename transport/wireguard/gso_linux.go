//go:build linux && !nogvisor

package wireguard

import (
	_ "unsafe"
)

//go:linkname gsoControlSize golang.zx2c4.com/wireguard/conn.gsoControlSize
var gsoControlSize int
