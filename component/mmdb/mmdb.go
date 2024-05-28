package mmdb

import (
	"sync"

	"github.com/oschwald/geoip2-golang"
	"github.com/phuslu/log"

	C "github.com/yaling888/quirktiva/constant"
)

var (
	mmdb *geoip2.Reader
	once sync.Once
)

func LoadFromBytes(buffer []byte) {
	once.Do(func() {
		var err error
		mmdb, err = geoip2.FromBytes(buffer)
		if err != nil {
			log.Fatal().
				Err(err).
				Msg("Can't load mmdb")
		}
	})
}

func Verify() bool {
	instance, err := geoip2.Open(C.Path.MMDB())
	if err == nil {
		_ = instance.Close()
	}
	return err == nil
}

func Instance() *geoip2.Reader {
	once.Do(func() {
		var err error
		mmdb, err = geoip2.Open(C.Path.MMDB())
		if err != nil {
			log.Fatal().
				Err(err).
				Msg("Can't load mmdb")
		}
	})

	return mmdb
}
