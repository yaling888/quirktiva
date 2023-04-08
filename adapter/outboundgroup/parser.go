package outboundgroup

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/common/structure"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"
)

var (
	errFormat            = errors.New("format error")
	errType              = errors.New("unsupported type")
	errMissProxy         = errors.New("`use` or `proxies` missing")
	errMissHealthCheck   = errors.New("`url` or `interval` missing")
	errDuplicateProvider = errors.New("duplicate provider name")
)

type GroupCommonOption struct {
	outbound.BasicOption
	Name       string   `group:"name"`
	Type       string   `group:"type"`
	Proxies    []string `group:"proxies,omitempty"`
	Use        []string `group:"use,omitempty"`
	URL        string   `group:"url,omitempty"`
	Interval   int      `group:"interval,omitempty"`
	Lazy       bool     `group:"lazy,omitempty"`
	DisableUDP bool     `group:"disable-udp,omitempty"`
	DisableDNS bool     `group:"disable-dns,omitempty"`
	Filter     string   `group:"filter,omitempty"`
}

func ParseProxyGroup(
	config map[string]any,
	proxyMap map[string]C.Proxy,
	providersMap map[string]types.ProxyProvider,
) (C.ProxyAdapter, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})

	groupOption := &GroupCommonOption{
		Lazy: true,
	}

	if err := decoder.Decode(config, groupOption); err != nil {
		return nil, errFormat
	}

	if groupOption.Type == "" || groupOption.Name == "" {
		return nil, errFormat
	}

	groupName := groupOption.Name

	if len(groupOption.Proxies) == 0 && len(groupOption.Use) == 0 {
		return nil, fmt.Errorf("%s: %w", groupName, errMissProxy)
	}

	if _, ok := providersMap[groupName]; ok {
		return nil, fmt.Errorf("%s: %w", groupName, errDuplicateProvider)
	}

	var filterRegx *regexp.Regexp
	if groupOption.Filter != "" {
		regx, err := regexp.Compile(groupOption.Filter)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid filter regex: %w", groupName, err)
		}
		filterRegx = regx
	}

	var hc *provider.HealthCheck

	// select and relay don't need health check
	if groupOption.Type == "select" || groupOption.Type == "relay" {
		hc = provider.NewHealthCheck([]C.Proxy{}, "", 0, true)
	} else {
		if groupOption.URL == "" || groupOption.Interval == 0 {
			return nil, fmt.Errorf("%s: %w", groupName, errMissHealthCheck)
		}
		hc = provider.NewHealthCheck([]C.Proxy{}, groupOption.URL, uint(groupOption.Interval), groupOption.Lazy)
	}

	pd, err := provider.NewCompatibleProvider(groupName, hc, filterRegx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", groupName, err)
	}

	if len(groupOption.Proxies) != 0 {
		ps, err := getProxies(proxyMap, groupOption.Proxies)
		if err != nil {
			pd.Finalize()
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		pd.SetProxies(ps)
	}

	if len(groupOption.Use) != 0 {
		list, err := getProviders(providersMap, groupOption.Use)
		if err != nil {
			pd.Finalize()
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		pd.SetProviders(list)
	}

	providers := []types.ProxyProvider{pd}
	providersMap[groupName] = pd

	var group C.ProxyAdapter
	switch groupOption.Type {
	case "url-test":
		opts := parseURLTestOption(config)
		group = NewURLTest(groupOption, providers, opts...)
	case "select":
		group = NewSelector(groupOption, providers)
	case "fallback":
		group = NewFallback(groupOption, providers)
	case "load-balance":
		strategy := parseStrategy(config)
		group, err = NewLoadBalance(groupOption, providers, strategy)
		if err != nil {
			pd.Finalize()
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}
	case "relay":
		group = NewRelay(groupOption, providers)
	default:
		pd.Finalize()
		return nil, fmt.Errorf("%s %w: %s", groupName, errType, groupOption.Type)
	}

	return group, nil
}

func getProxies(mapping map[string]C.Proxy, list []string) ([]C.Proxy, error) {
	var ps []C.Proxy
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func getProviders(mapping map[string]types.ProxyProvider, list []string) ([]types.ProxyProvider, error) {
	var ps []types.ProxyProvider
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}
		if p.VehicleType() == types.Compatible {
			return nil, fmt.Errorf("proxy group %s can't contains in `use`", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}
