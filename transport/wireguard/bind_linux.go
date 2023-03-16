package wireguard

import (
	_ "unsafe"
)

//go:linkname srcControlSize golang.zx2c4.com/wireguard/conn.srcControlSize
var srcControlSize int
