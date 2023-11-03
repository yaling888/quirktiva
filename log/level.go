package log

import (
	"encoding/json"
	"errors"

	logger "github.com/phuslu/log"
)

// LogLevelMapping is a mapping for LogLevel enum
var LogLevelMapping = map[string]LogLevel{
	FATAL.String():   FATAL,
	ERROR.String():   ERROR,
	WARNING.String(): WARNING,
	INFO.String():    INFO,
	DEBUG.String():   DEBUG,
	SILENT.String():  SILENT,
}

const (
	DEBUG   = LogLevel(logger.DebugLevel)
	INFO    = LogLevel(logger.InfoLevel)
	WARNING = LogLevel(logger.WarnLevel)
	ERROR   = LogLevel(logger.ErrorLevel)
	FATAL   = LogLevel(logger.FatalLevel)
	SILENT  = LogLevel(8)
)

type LogLevel int

// UnmarshalYAML unserialize LogLevel with yaml
func (l *LogLevel) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	_ = unmarshal(&tp)
	level, exist := LogLevelMapping[tp]
	if !exist {
		return errors.New("invalid mode")
	}
	*l = level
	return nil
}

// UnmarshalJSON unserialize LogLevel with json
func (l *LogLevel) UnmarshalJSON(data []byte) error {
	var tp string
	_ = json.Unmarshal(data, &tp)
	level, exist := LogLevelMapping[tp]
	if !exist {
		return errors.New("invalid mode")
	}
	*l = level
	return nil
}

// MarshalJSON serialize LogLevel with json
func (l LogLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

// MarshalYAML serialize LogLevel with yaml
func (l LogLevel) MarshalYAML() (any, error) {
	return l.String(), nil
}

func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "debug"
	case INFO:
		return "info"
	case WARNING:
		return "warning"
	case ERROR:
		return "error"
	case FATAL:
		return "fatal"
	case SILENT:
		return "silent"
	default:
		return "unknown"
	}
}
