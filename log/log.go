package log

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/phuslu/log"

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
	if log.IsTerminal(os.Stdout.Fd()) {
		timeFormat = "15:04:05"
		colorOutput = true
	}

	log.DefaultLogger = log.Logger{
		Level:      log.DebugLevel,
		TimeFormat: timeFormat,
		// Caller:     1,
		Writer: &writer{
			apiWriter:     &log.ConsoleWriter{Formatter: formatter, Writer: io.Discard},
			consoleWriter: &log.ConsoleWriter{ColorOutput: colorOutput, Writer: os.Stdout},
			consoleLevel:  log.InfoLevel,
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
	(log.DefaultLogger.Writer.(*writer)).consoleLevel = log.Level(newLevel)
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
	apiWriter     log.Writer
	consoleWriter log.Writer
	consoleLevel  log.Level
}

func (e *writer) Close() (err error) {
	for _, w := range []log.Writer{
		e.apiWriter,
		e.consoleWriter,
	} {
		if w == nil {
			continue
		}
		if closer, ok := w.(io.Closer); ok {
			if err1 := closer.Close(); err1 != nil {
				err = err1
			}
		}
	}
	return
}

func (e *writer) WriteEntry(entry *log.Entry) (n int, err error) {
	if tracing {
		_, _ = e.apiWriter.WriteEntry(entry)
	}

	if e.consoleWriter != nil && entry.Level >= e.consoleLevel {
		_, _ = e.consoleWriter.WriteEntry(entry)
	}

	return
}

func formatter(_ io.Writer, args *log.FormatterArgs) (n int, err error) {
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
