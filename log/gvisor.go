package log

import (
	"io"
	"runtime"
	"strings"
	"time"

	logger "github.com/phuslu/log"
	gLog "gvisor.dev/gvisor/pkg/log"
)

func init() {
	initGVisorLogger(true)
}

func initGVisorLogger(v bool) {
	if v {
		if _, ok := gLog.Log().Emitter.(*gVisorLogger); ok {
			return
		}
		gLog.SetTarget(&gVisorLogger{})
	} else {
		gLog.SetTarget(&gLog.Writer{Next: io.Discard})
	}
}

type gVisorLogger struct{}

func (gVisorLogger) Emit(depth int, level gLog.Level, _ time.Time, format string, args ...any) {
	if _, file, line, ok := runtime.Caller(1 + depth); ok {
		// Ignore (*gonet.TCPConn).RemoteAddr() warning: `ep.GetRemoteAddress() failed`.
		if line == 457 && strings.HasSuffix(file, "/pkg/tcpip/adapters/gonet/gonet.go") {
			return
		}
	}

	switch level {
	case gLog.Debug:
		logger.Debug().Msgf("[GVisor] "+format, args)
	case gLog.Info:
		logger.Info().Msgf("[GVisor] "+format, args)
	case gLog.Warning:
		logger.Warn().Msgf("[GVisor] "+format, args)
	}
}
