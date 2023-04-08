package outboundgroup

import (
	"time"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
)

const (
	defaultGetProxiesDuration = time.Second * 5
)

func getProvidersProxies(providers []provider.ProxyProvider, touch bool) []C.Proxy {
	proxies := []C.Proxy{}
	for _, pd := range providers {
		if touch {
			pd.Touch()
		}
		proxies = append(proxies, pd.Proxies()...)
	}
	return proxies
}

func touchProvidersProxies(providers []provider.ProxyProvider) {
	for _, pd := range providers {
		pd.Touch()
	}
}
