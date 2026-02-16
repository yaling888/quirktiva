package log

import (
	"bytes"
	"log"

	logger "github.com/phuslu/log"
)

func init() {
	log.SetFlags(0)
	log.SetOutput(&stdWriter{})
}

type stdWriter struct{}

func (hl *stdWriter) Write(p []byte) (n int, err error) {
	p = bytes.TrimRightFunc(p, func(r rune) bool {
		return r == 10
	})
	logger.Debug().Msgf("[STD] %s", p)
	return
}
