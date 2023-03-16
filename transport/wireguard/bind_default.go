//go:build !windows

package wireguard

import (
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
)

func NewDefaultBind(
	controlFns []func(network, address string, c syscall.RawConn) error,
	interfaceName string,
	reserved []byte,
) conn.Bind {
	return NewStdNetBind(controlFns, interfaceName, reserved)
}
