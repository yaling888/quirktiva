package provider

import (
	"context"
	"time"

	"go.uber.org/atomic"

	"github.com/Dreamacro/clash/common/batch"
	C "github.com/Dreamacro/clash/constant"
)

const (
	defaultURLTestTimeout = time.Second * 5
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type HealthCheck struct {
	url       string
	proxies   []C.Proxy
	proxiesFn func() []C.Proxy
	interval  uint
	lazy      bool
	lastTouch *atomic.Int64
	ticker    *time.Ticker
	done      chan struct{}
}

func (hc *HealthCheck) process() {
	if hc.ticker != nil {
		return
	}

	hc.ticker = time.NewTicker(time.Duration(hc.interval) * time.Second)

	for {
		select {
		case <-hc.ticker.C:
			now := time.Now().Unix()
			if !hc.lazy || now-hc.lastTouch.Load() < int64(hc.interval) {
				hc.check()
			}
		case <-hc.done:
			hc.ticker.Stop()
			hc.ticker = nil
			return
		}
	}
}

func (hc *HealthCheck) setProxy(proxies []C.Proxy) {
	hc.proxies = proxies
}

func (hc *HealthCheck) setProxyFn(proxiesFn func() []C.Proxy) {
	hc.proxiesFn = proxiesFn
}

func (hc *HealthCheck) auto() bool {
	return hc.interval != 0
}

func (hc *HealthCheck) touch() {
	hc.lastTouch.Store(time.Now().Unix())
}

func (hc *HealthCheck) check() {
	var proxies []C.Proxy
	if hc.proxiesFn != nil {
		proxies = hc.proxiesFn()
	} else {
		proxies = hc.proxies
	}
	if len(proxies) == 0 {
		return
	}
	b, _ := batch.New[bool](context.Background(), batch.WithConcurrencyNum[bool](10))
	for _, proxy := range proxies {
		p := proxy
		b.Go(p.Name(), func() (bool, error) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
			defer cancel()
			_, _, _ = p.URLTest(ctx, hc.url)
			return false, nil
		})
	}
	b.Wait()
}

func (hc *HealthCheck) close() {
	if hc.ticker != nil {
		hc.done <- struct{}{}
	}
	hc.interval = 0
	hc.proxiesFn = nil
	hc.proxies = nil
}

func NewHealthCheck(proxies []C.Proxy, url string, interval uint, lazy bool) *HealthCheck {
	return &HealthCheck{
		proxies:   proxies,
		url:       url,
		interval:  interval,
		lazy:      lazy,
		lastTouch: atomic.NewInt64(0),
		done:      make(chan struct{}, 1),
	}
}
