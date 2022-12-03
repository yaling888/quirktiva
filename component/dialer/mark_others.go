//go:build !linux && !freebsd && !openbsd

package dialer

import (
	"net"
	"net/netip"
	"sync"

	"github.com/phuslu/log"
)

var printMarkWarnOnce sync.Once

func printMarkWarn() {
	printMarkWarnOnce.Do(func() {
		log.Warn().Msg("Routing mark on socket is not supported on current platform")
	})
}

func bindMarkToDialer(mark int, dialer *net.Dialer, _ string, _ netip.Addr) {
	printMarkWarn()
}

func bindMarkToListenConfig(mark int, lc *net.ListenConfig, _, _ string) {
	printMarkWarn()
}
