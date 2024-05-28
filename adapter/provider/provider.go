package provider

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	regexp "github.com/dlclark/regexp2"
	"github.com/phuslu/log"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	"github.com/yaling888/quirktiva/adapter"
	"github.com/yaling888/quirktiva/adapter/outbound"
	"github.com/yaling888/quirktiva/common/convert"
	"github.com/yaling888/quirktiva/common/singledo"
	"github.com/yaling888/quirktiva/common/structure"
	"github.com/yaling888/quirktiva/component/resolver"
	C "github.com/yaling888/quirktiva/constant"
	types "github.com/yaling888/quirktiva/constant/provider"
	"github.com/yaling888/quirktiva/tunnel/statistic"
)

var (
	group  = &singledo.Group[[]C.Proxy]{}
	reject = adapter.NewProxy(outbound.NewReject())
)

const (
	ReservedName = "default"
)

type ProxySchema struct {
	Proxies []C.RawProxy `yaml:"proxies"`
}

var _ types.ProxyProvider = (*ProxySetProvider)(nil)

type ProxySetProvider struct {
	healthCheck *HealthCheck
	proxies     []C.Proxy
	groupNames  []string
	globalFCV   bool
	tmCheck     *time.Timer

	mux  sync.Mutex // guards following fields
	hash [16]byte   // config file hash
	*fetcher[[]C.Proxy]
}

func (pp *ProxySetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":         pp.Name(),
		"type":         pp.Type().String(),
		"vehicleType":  pp.VehicleType().String(),
		"proxies":      pp.Proxies(),
		"subscription": pp.subscription(),
		"updatedAt":    pp.updatedAt,
	})
}

func (pp *ProxySetProvider) Name() string {
	return pp.name
}

func (pp *ProxySetProvider) HealthCheck() {
	pp.healthCheck.checkAll()
}

func (pp *ProxySetProvider) Update() error {
	defer runtime.GC()

	pp.mux.Lock()

	buf, err := os.ReadFile(C.Path.Config())
	if err != nil {
		pp.mux.Unlock()
		return err
	}

	hash := md5.Sum(buf)
	if !bytes.Equal(pp.hash[:], hash[:]) {
		pp.mux.Unlock()

		rawCfg := struct {
			ProxyProvider map[string]map[string]any `yaml:"proxy-providers"`
		}{}

		if err = yaml.Unmarshal(buf, &rawCfg); err != nil {
			return err
		}

		decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})

		schema := &proxyProviderSchema{ForceCertVerify: pp.globalFCV}

		for name, mapping := range rawCfg.ProxyProvider {
			if name == pp.name {
				if err := decoder.Decode(mapping, schema); err != nil {
					return err
				}
				break
			}
		}

		vehicle, err := newVehicle(schema)
		if err != nil {
			return err
		}

		option := adapter.ProxyOption{
			ForceCertVerify: schema.ForceCertVerify,
			ForceUDP:        schema.UDP,
			DisableUDP:      schema.DisableUDP,
			DisableDNS:      schema.DisableDNS,
			RandomHost:      schema.RandomHost,
			PrefixName:      schema.PrefixName,
			AutoCipher:      true,
		}

		pp.mux.Lock()

		_, err = newOrUpdateFetcher(pp.name, schema.Interval, schema.Filter, vehicle, nil, pp.globalFCV, option, pp)
		if err != nil {
			pp.mux.Unlock()
			return err
		}

		pp.hash = hash
	}
	pp.mux.Unlock()

	elm, same, err := pp.fetcher.Update()
	if err != nil {
		return err
	}
	if same {
		log.Info().Str("name", pp.Name()).Msg("[Provider] proxies doesn't change")
		return nil
	}

	pp.onUpdate(elm)
	return nil
}

func (pp *ProxySetProvider) Initial() error {
	proxies, err := pp.fetcher.Initial()
	if err != nil {
		return err
	}

	if proxies == nil {
		name := pp.name + "-" + "Reject"
		proxies = append(proxies, adapter.NewProxy(outbound.NewRejectByName(name)))
	}
	pp.onUpdate(proxies)
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
	if pp.tmCheck != nil {
		pp.tmCheck.Stop()
		pp.tmCheck = nil
	}
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
			go func() {
				p.Cleanup()
				resolver.RemoveCache(name)
			}()
			return name
		})
		statistic.DefaultManager.KickOut(names...)
		go pp.healthCheck.checkAll()
	} else {
		pp.tmCheck = time.AfterFunc(45*time.Second, func() {
			pp.healthCheck.checkAll()
			pp.tmCheck = nil
		})
	}
}

func (pp *ProxySetProvider) addGroupName(name string) {
	pp.groupNames = append(pp.groupNames, name)
}

func (pp *ProxySetProvider) subscription() *Subscription {
	if s, ok := pp.vehicle.(interface{ Subscription() *Subscription }); ok {
		return s.Subscription()
	}
	return nil
}

func NewProxySetProvider(
	name string,
	interval time.Duration,
	filter string,
	vehicle types.Vehicle,
	hc *HealthCheck,
	globalForceCertVerify bool,
	option adapter.ProxyOption,
) (*ProxySetProvider, error) {
	return newOrUpdateFetcher(name, interval, filter, vehicle, hc, globalForceCertVerify, option, nil)
}

func newOrUpdateFetcher(
	name string,
	interval time.Duration,
	filter string,
	vehicle types.Vehicle,
	hc *HealthCheck,
	globalForceCertVerify bool,
	option adapter.ProxyOption,
	pd *ProxySetProvider,
) (*ProxySetProvider, error) {
	var filterReg *regexp.Regexp
	if filter != "" {
		f, err := regexp.Compile(filter, 0)
		if err != nil {
			return nil, fmt.Errorf("invalid filter regex: %w", err)
		}
		filterReg = f
	}

	if pd == nil {
		if hc.auto() {
			go hc.process()
		}

		pd = &ProxySetProvider{
			proxies:     []C.Proxy{},
			healthCheck: hc,
			globalFCV:   globalForceCertVerify,
		}
	} else {
		_ = pd.fetcher.Destroy()
	}

	pd.fetcher = newFetcher[[]C.Proxy](
		name,
		interval,
		vehicle,
		proxiesParseAndFilter(filterReg, option),
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
	tmCheck     *time.Timer

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
	cp.healthCheck.checkAll()
}

func (cp *CompatibleProvider) Update() error {
	return nil
}

func (cp *CompatibleProvider) Initial() error {
	cp.Forget()
	if cp.hasProxy && !cp.hasProvider {
		cp.healthCheckWait()
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
							rs, _ := cp.filterRegx.MatchString(proxy.Name())
							return rs
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

	if !hitCache {
		cp.healthCheckWait()
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
	if cp.tmCheck != nil {
		cp.tmCheck.Stop()
		cp.tmCheck = nil
	}
	cp.healthCheck.close()
	cp.providers = nil
	cp.Forget()
}

func (cp *CompatibleProvider) healthCheckWait() {
	if cp.tmCheck != nil || !cp.healthCheck.auto() {
		return
	}
	cp.tmCheck = time.AfterFunc(30*time.Second, func() {
		if cp.healthCheck.auto() {
			cp.healthCheck.checkAll()
		}
		cp.tmCheck = nil
	})
}

func NewCompatibleProvider(name string, hc *HealthCheck, filterRegx *regexp.Regexp) (*CompatibleProvider, error) {
	if hc.auto() {
		go hc.process()
	}

	pd := &CompatibleProvider{
		name:        name,
		healthCheck: hc,
		filterRegx:  filterRegx,
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

func proxiesParseAndFilter(filterReg *regexp.Regexp, option adapter.ProxyOption) parser[[]C.Proxy] {
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
			schema.Proxies = lo.Map(proxies, func(m map[string]any, _ int) C.RawProxy {
				return C.RawProxy{M: m}
			})
		}

		if len(schema.Proxies) == 0 {
			return nil, errors.New("file must have a `proxies` field")
		}

		proxies := make([]C.Proxy, 0)
		for idx, ps := range schema.Proxies {
			ps.Init()
			mapping := ps.M
			name, ok := mapping["name"].(string)
			if ok && filterReg != nil {
				matched, err := filterReg.MatchString(name)
				if err != nil {
					return nil, fmt.Errorf("match filter regex failed: %w", err)
				}
				if !matched {
					continue
				}
			}

			if option.PrefixName != "" {
				mapping["name"] = option.PrefixName + name
			}

			proxy, err := adapter.ParseProxy(mapping, option)
			if err != nil {
				return nil, fmt.Errorf("proxy %s[index: %d] error: %w", name, idx, err)
			}
			proxies = append(proxies, proxy)
		}

		if len(proxies) == 0 {
			if filterReg != nil {
				return nil, errors.New("doesn't match any proxy, please check your filter")
			}
			return nil, errors.New("file doesn't have any proxy")
		}

		return proxies, nil
	}
}
