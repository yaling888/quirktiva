package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/samber/lo"
	"go.uber.org/atomic"
	"gopkg.in/yaml.v3"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/convert"
	"github.com/Dreamacro/clash/common/singledo"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/tunnel/statistic"
)

var (
	group  = &singledo.Group[[]C.Proxy]{}
	reject = adapter.NewProxy(outbound.NewReject())
)

const (
	ReservedName = "default"
)

type ProxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
}

var _ types.ProxyProvider = (*ProxySetProvider)(nil)

type ProxySetProvider struct {
	*fetcher[[]C.Proxy]
	healthCheck *HealthCheck
	proxies     []C.Proxy
	groupNames  []string
}

func (pp *ProxySetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        pp.Name(),
		"type":        pp.Type().String(),
		"vehicleType": pp.VehicleType().String(),
		"proxies":     pp.Proxies(),
		"updatedAt":   pp.updatedAt,
	})
}

func (pp *ProxySetProvider) Name() string {
	return pp.name
}

func (pp *ProxySetProvider) HealthCheck() {
	pp.healthCheck.check()
}

func (pp *ProxySetProvider) Update() error {
	elm, same, err := pp.fetcher.Update()
	if err == nil && !same {
		pp.onUpdate(elm)
	}
	return err
}

func (pp *ProxySetProvider) Initial() error {
	elm, err := pp.fetcher.Initial()
	if err != nil {
		return err
	}

	pp.onUpdate(elm)
	return nil
}

func (pp *ProxySetProvider) Type() types.ProviderType {
	return types.Proxy
}

func (pp *ProxySetProvider) Proxies() []C.Proxy {
	return pp.proxies
}

func (pp *ProxySetProvider) Touch() {
	pp.healthCheck.touch()
}

func (pp *ProxySetProvider) Finalize() {
	pp.healthCheck.close()
	_ = pp.fetcher.Destroy()
}

func (pp *ProxySetProvider) setProxies(proxies []C.Proxy) {
	old := pp.proxies
	pp.proxies = proxies
	pp.healthCheck.setProxy(proxies)

	for _, name := range pp.groupNames {
		group.Forget(name)
	}

	if len(old) != 0 {
		names := lo.Map(old, func(item C.Proxy, _ int) string {
			p := item.(C.ProxyAdapter)
			name := p.Name()
			go p.Cleanup()
			return name
		})
		statistic.DefaultManager.KickOut(names...)
		if pp.healthCheck.auto() {
			go pp.healthCheck.check()
		}
	} else if pp.healthCheck.auto() {
		go func() {
			time.Sleep(45 * time.Second)
			if pp.healthCheck.auto() {
				pp.healthCheck.check()
			}
		}()
	}
}

func (pp *ProxySetProvider) addGroupName(name string) {
	pp.groupNames = append(pp.groupNames, name)
}

func NewProxySetProvider(
	name string,
	interval time.Duration,
	filter string,
	vehicle types.Vehicle,
	hc *HealthCheck,
	forceCertVerify bool,
	udp bool,
	randomHost bool,
	prefixName string,
) (*ProxySetProvider, error) {
	filterReg, err := regexp.Compile(filter)
	if err != nil {
		return nil, fmt.Errorf("invalid filter regex: %w", err)
	}

	if hc.auto() {
		go hc.process()
	}

	pd := &ProxySetProvider{
		proxies:     []C.Proxy{},
		healthCheck: hc,
	}

	pd.fetcher = newFetcher[[]C.Proxy](
		name,
		interval,
		vehicle,
		proxiesParseAndFilter(filter, filterReg, forceCertVerify, udp, randomHost, prefixName),
		proxiesOnUpdate(pd),
	)

	return pd, nil
}

var _ types.ProxyProvider = (*CompatibleProvider)(nil)

type CompatibleProvider struct {
	name        string
	proxies     []C.Proxy
	providers   []types.ProxyProvider
	healthCheck *HealthCheck
	filterRegx  *regexp.Regexp
	hcWait      *atomic.Bool

	hasProxy    bool
	hasProvider bool
}

func (cp *CompatibleProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        cp.Name(),
		"type":        cp.Type().String(),
		"vehicleType": cp.VehicleType().String(),
		"proxies":     cp.Proxies(),
	})
}

func (cp *CompatibleProvider) Name() string {
	return cp.name
}

func (cp *CompatibleProvider) HealthCheck() {
	cp.healthCheck.check()
}

func (cp *CompatibleProvider) Update() error {
	return nil
}

func (cp *CompatibleProvider) Initial() error {
	cp.Forget()
	if cp.hasProxy && !cp.hasProvider {
		if cp.healthCheck.auto() {
			go cp.healthCheckWait()
		}
	} else if len(cp.Proxies()) == 0 {
		return errors.New("provider need one proxy at least")
	}
	return nil
}

func (cp *CompatibleProvider) VehicleType() types.VehicleType {
	return types.Compatible
}

func (cp *CompatibleProvider) Type() types.ProviderType {
	return types.Proxy
}

func (cp *CompatibleProvider) Proxies() []C.Proxy {
	if !cp.hasProvider {
		return cp.proxies
	}

	proxies, _, hitCache := group.Do(cp.name, func() ([]C.Proxy, error) {
		var proxies []C.Proxy
		if cp.filterRegx != nil {
			proxies = lo.FlatMap(
				cp.providers,
				func(provider types.ProxyProvider, _ int) []C.Proxy {
					return lo.Filter(
						provider.Proxies(),
						func(proxy C.Proxy, _ int) bool {
							return cp.filterRegx.MatchString(proxy.Name())
						})
				})

			if cp.hasProxy {
				if len(proxies) == 0 {
					return cp.proxies, nil
				}
				proxies = append(cp.proxies, proxies...)
			} else if len(proxies) == 0 {
				proxies = append(proxies, reject)
			}
		} else {
			proxies = lo.FlatMap(
				cp.providers,
				func(pd types.ProxyProvider, _ int) []C.Proxy {
					return pd.Proxies()
				})

			if cp.hasProxy {
				proxies = append(cp.proxies, proxies...)
			}
		}

		return proxies, nil
	})

	if !hitCache && cp.healthCheck.auto() {
		go cp.healthCheckWait()
	}

	return proxies
}

func (cp *CompatibleProvider) Touch() {
	cp.healthCheck.touch()
}

func (cp *CompatibleProvider) SetProxies(proxies []C.Proxy) {
	cp.proxies = proxies
	cp.hasProxy = len(cp.proxies) != 0
}

func (cp *CompatibleProvider) SetProviders(providers []types.ProxyProvider) {
	for _, elem := range providers {
		if e, ok := elem.(*ProxySetProvider); ok {
			e.addGroupName(cp.Name())
		}
	}
	cp.providers = providers
	cp.hasProvider = len(cp.providers) != 0
}

func (cp *CompatibleProvider) Forget() {
	group.Forget(cp.name)
}

func (cp *CompatibleProvider) Finalize() {
	cp.healthCheck.close()
	cp.providers = nil
	cp.Forget()
}

func (cp *CompatibleProvider) healthCheckWait() {
	if cp.hcWait.Load() {
		return
	}
	cp.hcWait.Store(true)
	time.Sleep(30 * time.Second)
	if cp.healthCheck.auto() {
		cp.healthCheck.check()
	}
	cp.hcWait.Store(false)
}

func NewCompatibleProvider(name string, hc *HealthCheck, filterRegx *regexp.Regexp) (*CompatibleProvider, error) {
	if hc.auto() {
		go hc.process()
	}

	pd := &CompatibleProvider{
		name:        name,
		healthCheck: hc,
		filterRegx:  filterRegx,
		hcWait:      atomic.NewBool(false),
	}

	hc.setProxyFn(func() []C.Proxy {
		return pd.Proxies()
	})

	return pd, nil
}

func proxiesOnUpdate(pd *ProxySetProvider) func([]C.Proxy) {
	return func(elm []C.Proxy) {
		pd.setProxies(elm)
	}
}

func proxiesParseAndFilter(filter string, filterReg *regexp.Regexp, forceCertVerify, udp, randomHost bool, prefixName string) parser[[]C.Proxy] {
	return func(buf []byte) ([]C.Proxy, error) {
		schema := &ProxySchema{}

		if err := yaml.Unmarshal(buf, schema); err != nil {
			proxies, err1 := convert.ConvertsV2Ray(buf)
			if err1 != nil {
				proxies, err1 = convert.ConvertsWireGuard(buf)
			}
			if err1 != nil {
				return nil, errors.New("parse proxy provider failure, invalid data format")
			}
			schema.Proxies = proxies
		}

		if len(schema.Proxies) == 0 {
			return nil, errors.New("file must have a `proxies` field")
		}

		proxies := []C.Proxy{}
		for idx, mapping := range schema.Proxies {
			name, ok := mapping["name"].(string)
			if ok && len(filter) > 0 && !filterReg.MatchString(name) {
				continue
			}

			if prefixName != "" {
				mapping["name"] = prefixName + name
			}

			proxy, err := adapter.ParseProxy(mapping, forceCertVerify, udp, true, randomHost)
			if err != nil {
				return nil, fmt.Errorf("proxy %s[index: %d] error: %w", name, idx, err)
			}
			proxies = append(proxies, proxy)
		}

		if len(proxies) == 0 {
			if len(filter) > 0 {
				return nil, errors.New("doesn't match any proxy, please check your filter")
			}
			return nil, errors.New("file doesn't have any proxy")
		}

		return proxies, nil
	}
}
