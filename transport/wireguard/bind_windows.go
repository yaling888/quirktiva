package wireguard

import (
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/winrio"
)

func NewDefaultBind(
	controlFns []func(network, address string, c syscall.RawConn) error,
	interfaceName string,
	reserved []byte,
) conn.Bind {
	if !winrio.Initialize() {
		return NewStdNetBind(controlFns, interfaceName, reserved)
	}
	return new(conn.WinRingBind)
}
