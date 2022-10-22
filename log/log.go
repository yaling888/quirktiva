package log

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
	_ "unsafe"

	logger "github.com/phuslu/log"

	"github.com/Dreamacro/clash/common/observable"
)

var (
	textCh     = make(chan Event)
	jsonCh     = make(chan Event)
	textSource = observable.NewObservable[Event](textCh)
	jsonSource = observable.NewObservable[Event](jsonCh)

	level       = INFO
	tracing     = false
	enabledText = false
	enabledJson = false

	bbPool = sync.Pool{
		New: func() any {
			return new(bb)
		},
	}
)

func init() {
	var (
		timeFormat  = time.RFC3339
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
		Writer: &multiWriter{
			textWriter:    &logger.IOWriter{Writer: &apiWriter{isJson: false}},
			jsonWriter:    &logger.IOWriter{Writer: &apiWriter{isJson: true}},
			consoleWriter: &logger.ConsoleWriter{ColorOutput: colorOutput, Writer: os.Stdout},
			consoleLevel:  logger.InfoLevel,
		},
	}
}

func SubscribeText() observable.Subscription[Event] {
	sub, _ := textSource.Subscribe()
	enabledText = true
	return sub
}

func UnSubscribeText(sub observable.Subscription[Event]) {
	textSource.UnSubscribe(sub)
	if !textSource.HasSubscriber() {
		enabledText = false
	}
}

func SubscribeJson() observable.Subscription[Event] {
	sub, _ := jsonSource.Subscribe()
	enabledJson = true
	return sub
}

func UnSubscribeJson(sub observable.Subscription[Event]) {
	jsonSource.UnSubscribe(sub)
	if !jsonSource.HasSubscriber() {
		enabledJson = false
	}
}

func Level() LogLevel {
	return level
}

func SetLevel(newLevel LogLevel) {
	level = newLevel
	(logger.DefaultLogger.Writer.(*multiWriter)).consoleLevel = logger.Level(newLevel)
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

type apiWriter struct {
	isJson bool
}

func (fw *apiWriter) Write(p []byte) (n int, err error) {
	b := bbPool.Get().(*bb)
	b.B = b.B[:0]
	defer bbPool.Put(b)

	b.B = append(b.B, p...)

	var (
		args     logger.FormatterArgs
		logLevel LogLevel
	)

	parseFormatterArgs(b.B, &args)

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

	if fw.isJson {
		formatJson(logLevel, p)
	} else {
		formatText(logLevel, &args)
	}
	return
}

type multiWriter struct {
	textWriter    logger.Writer
	jsonWriter    logger.Writer
	consoleWriter logger.Writer
	consoleLevel  logger.Level
}

func (e *multiWriter) Close() (err error) {
	if closer, ok := e.consoleWriter.(io.Closer); ok {
		if err1 := closer.Close(); err1 != nil {
			err = err1
		}
	}
	return
}

func (e *multiWriter) WriteEntry(entry *logger.Entry) (n int, err error) {
	if tracing {
		if enabledText {
			_, _ = e.textWriter.WriteEntry(entry)
		}
		if enabledJson {
			_, _ = e.jsonWriter.WriteEntry(entry)
		}
	}

	if entry.Level >= e.consoleLevel {
		_, _ = e.consoleWriter.WriteEntry(entry)
	}
	return
}

func formatText(logLevel LogLevel, args *logger.FormatterArgs) {
	b := bbPool.Get().(*bb)
	b.B = b.B[:0]
	defer bbPool.Put(b)

	_, _ = fmt.Fprintf(b, " %s", args.Message)

	for _, kv := range args.KeyValues {
		_, _ = fmt.Fprintf(b, " %s=%s", kv.Key, kv.Value)
	}

	event := Event{
		LogLevel: logLevel,
		Payload:  string(b.B),
	}

	textCh <- event
}

func formatJson(logLevel LogLevel, p []byte) {
	event := Event{
		LogLevel: logLevel,
		Payload:  string(p),
	}

	jsonCh <- event
}

//go:linkname parseFormatterArgs github.com/phuslu/log.parseFormatterArgs
func parseFormatterArgs(_ []byte, _ *logger.FormatterArgs)
