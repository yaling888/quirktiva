//go:build !linux && !freebsd && !openbsd

package dialer

import (
	"net"
	"net/netip"
	"sync"

	"github.com/phuslu/log"
)

var printMarkWarn = sync.OnceFunc(func() {
	log.Warn().Msg("Routing mark on socket is not supported on current platform")
})

func bindMarkToDialer(_ int, _ *net.Dialer, _ string, _ netip.Addr) {
	printMarkWarn()
}

func bindMarkToListenConfig(_ int, _ *net.ListenConfig, _, _ string) {
	printMarkWarn()
}
