//go:build !nogvisor

package log

import (
	"io"
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

func (gVisorLogger) Emit(_ int, level gLog.Level, _ time.Time, format string, args ...any) {
	switch level {
	case gLog.Debug:
		logger.Debug().Msgf("[GVisor] "+format, args)
	case gLog.Info:
		logger.Info().Msgf("[GVisor] "+format, args)
	case gLog.Warning:
		logger.Warn().Msgf("[GVisor] "+format, args)
	}
}

func SetLevel(newLevel LogLevel) {
	level = newLevel
	(logger.DefaultLogger.Writer.(*multiWriter)).consoleLevel = logger.Level(newLevel)

	if !jsonSource.HasSubscriber() && !textSource.HasSubscriber() {
		logger.DefaultLogger.SetLevel(logger.Level(newLevel))
	}

	gLevel := gLog.Warning
	if newLevel == DEBUG {
		gLevel = gLog.Debug
	} else if newLevel == INFO {
		gLevel = gLog.Info
	}
	gLog.SetLevel(gLevel)
	initGVisorLogger(newLevel != SILENT)
}
