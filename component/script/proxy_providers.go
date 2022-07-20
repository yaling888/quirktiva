package script

import (
	"fmt"

	"go.starlark.net/starlark"

	C "github.com/Dreamacro/clash/constant"
)

var _ starlark.Mapping = (*ProxyProviders)(nil)

type ProxyProviders struct {
	starlark.Value
}

func (p *ProxyProviders) Type() string {
	return "proxy_providers"
}

func (p *ProxyProviders) Get(value starlark.Value) (v starlark.Value, found bool, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("call proxy_providers error: %w", err)
		}
	}()

	var name starlark.String
	if name, found = value.(starlark.String); !found {
		err = fmt.Errorf("invalid key type")
		return
	}
	providerName := name.GoString()

	var proxies []C.Proxy
	if proxies, found = C.GetScriptProxyProviders()[providerName]; !found {
		err = fmt.Errorf("provider [%s] not found", providerName)
		return
	}

	var array []starlark.Value
	for _, proxy := range proxies {
		dict := starlark.NewDict(3)
		err = dict.SetKey(starlark.String("name"), starlark.String(proxy.Name()))
		if err != nil {
			return
		}
		err = dict.SetKey(starlark.String("alive"), starlark.Bool(proxy.Alive()))
		if err != nil {
			return
		}
		err = dict.SetKey(starlark.String("delay"), starlark.MakeUint64(uint64(proxy.LastDelay())))
		if err != nil {
			return
		}
		array = append(array, dict)
	}

	v = starlark.NewList(array)
	return
}

func newProxyProviders() *ProxyProviders {
	return &ProxyProviders{}
}
