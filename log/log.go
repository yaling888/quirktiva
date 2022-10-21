package log

import (
	"fmt"
	"io"
	"os"
	"sync"

	logger "github.com/phuslu/log"

	"github.com/Dreamacro/clash/common/observable"
)

var (
	logCh   = make(chan Event)
	source  = observable.NewObservable[Event](logCh)
	level   = INFO
	tracing = false

	bbPool = sync.Pool{
		New: func() any {
			return new(bb)
		},
	}
)

func init() {
	var (
		timeFormat  = "2006-01-02 15:04:05"
		colorOutput = false
	)
	if logger.IsTerminal(os.Stdout.Fd()) {
		timeFormat = "15:04:05"
		colorOutput = true
	}

	logger.DefaultLogger = logger.Logger{
		Level:      logger.DebugLevel,
		TimeFormat: timeFormat,
		// Caller:     1,
		Writer: &writer{
			apiWriter:     &logger.ConsoleWriter{Formatter: formatter, Writer: io.Discard},
			consoleWriter: &logger.ConsoleWriter{ColorOutput: colorOutput, Writer: os.Stdout},
			consoleLevel:  logger.InfoLevel,
		},
	}
}

func Subscribe() observable.Subscription[Event] {
	sub, _ := source.Subscribe()
	return sub
}

func UnSubscribe(sub observable.Subscription[Event]) {
	source.UnSubscribe(sub)
}

func Level() LogLevel {
	return level
}

func SetLevel(newLevel LogLevel) {
	level = newLevel
	(logger.DefaultLogger.Writer.(*writer)).consoleLevel = logger.Level(newLevel)
}

func SetTracing(t bool) {
	tracing = t
}

type Event struct {
	LogLevel LogLevel
	Payload  string
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

type bb struct {
	B []byte
}

func (b *bb) Write(p []byte) (int, error) {
	b.B = append(b.B, p...)
	return len(p), nil
}

type writer struct {
	apiWriter     logger.Writer
	consoleWriter logger.Writer
	consoleLevel  logger.Level
}

func (e *writer) Close() (err error) {
	if closer, ok := e.apiWriter.(io.Closer); ok {
		if err1 := closer.Close(); err1 != nil {
			err = err1
		}
	}
	if closer, ok := e.consoleWriter.(io.Closer); ok {
		if err1 := closer.Close(); err1 != nil {
			err = err1
		}
	}
	return
}

func (e *writer) WriteEntry(entry *logger.Entry) (n int, err error) {
	if tracing {
		_, _ = e.apiWriter.WriteEntry(entry)
	}

	if entry.Level >= e.consoleLevel {
		_, _ = e.consoleWriter.WriteEntry(entry)
	}

	return
}

func formatter(_ io.Writer, args *logger.FormatterArgs) (n int, err error) {
	b := bbPool.Get().(*bb)
	b.B = b.B[:0]
	defer bbPool.Put(b)

	var logLevel LogLevel
	switch args.Level {
	case "debug":
		logLevel = DEBUG
	case "info":
		logLevel = INFO
	case "warn":
		logLevel = WARNING
	case "error":
		logLevel = ERROR
	default:
		logLevel = SILENT
	}

	_, _ = fmt.Fprintf(b, " %s", args.Message)

	for _, kv := range args.KeyValues {
		_, _ = fmt.Fprintf(b, " %s=%s", kv.Key, kv.Value)
	}

	event := Event{
		LogLevel: logLevel,
		Payload:  string(b.B),
	}

	logCh <- event

	return 0, nil
}
