package dialer

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

type controlFn = func(network, address string, c syscall.RawConn) error

func bindMarkToDialer(mark int, dialer *net.Dialer, _ string, _ netip.Addr) {
	dialer.Control = bindMarkToControl(mark, dialer.Control)
}

func bindMarkToListenConfig(mark int, lc *net.ListenConfig, _, _ string) {
	lc.Control = bindMarkToControl(mark, lc.Control)
}

func bindMarkToControl(mark int, chain controlFn) controlFn {
	return func(network, address string, c syscall.RawConn) (err error) {
		defer func() {
			if err == nil && chain != nil {
				err = chain(network, address, c)
			}
		}()

		addrPort, err := netip.ParseAddrPort(address)
		if err == nil && !addrPort.Addr().IsGlobalUnicast() {
			return
		}

		var innerErr error
		err = c.Control(func(fd uintptr) {
			innerErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RTABLE, mark)
		})
		if err == nil && innerErr != nil {
			err = innerErr
		}
		return
	}
}
