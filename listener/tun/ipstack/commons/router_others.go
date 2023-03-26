//go:build !darwin && !linux && !windows

package commons

import (
	"fmt"
	"net/netip"
	"runtime"

	"github.com/Dreamacro/clash/listener/tun/device"
)

func ConfigInterfaceAddress(_ device.Device, _ netip.Prefix, _ int, _ bool) error {
	return nil
}

func StartDefaultInterfaceChangeMonitor() {}

func StopDefaultInterfaceChangeMonitor() {}

func defaultRouteInterface() (*DefaultInterface, error) {
	return nil, fmt.Errorf(
		"can not auto detect interface on this OS: %s, you must assign value to `interface-name` by manual",
		runtime.GOOS,
	)
}
