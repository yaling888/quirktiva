//go:build nogvisor

package log

import logger "github.com/phuslu/log"

func SetLevel(newLevel LogLevel) {
	level = newLevel
	(logger.DefaultLogger.Writer.(*multiWriter)).consoleLevel = logger.Level(newLevel)

	if !jsonSource.HasSubscriber() && !textSource.HasSubscriber() {
		logger.DefaultLogger.SetLevel(logger.Level(newLevel))
	}
}
