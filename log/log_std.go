package log

import (
	"bytes"
	"errors"
	"log"

	logger "github.com/phuslu/log"
)

func init() {
	log.SetFlags(0)
	log.SetOutput(&stdWriter{})
}

type stdWriter struct{}

func (hl *stdWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	if n < 2 {
		return
	}
	s := "[STD]"
	i := bytes.IndexByte(p, ':')
	if i == -1 {
		i = 0
	} else {
		s += " " + string(p[:i])
		i = min(i+2, n-2)
	}
	logger.Debug().Err(errors.New(string(p[i : n-1]))).Msg(s)
	return
}
