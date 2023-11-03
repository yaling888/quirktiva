package provider

import (
	"errors"
	"fmt"
	"time"

	"github.com/yaling888/clash/adapter"
	"github.com/yaling888/clash/common/structure"
	C "github.com/yaling888/clash/constant"
	types "github.com/yaling888/clash/constant/provider"
)

var errVehicleType = errors.New("unsupport vehicle type")

type healthCheckSchema struct {
	Enable   bool          `provider:"enable"`
	URL      string        `provider:"url"`
	Interval time.Duration `provider:"interval"`
	Lazy     bool          `provider:"lazy,omitempty"`
}

type proxyProviderSchema struct {
	Type            string              `provider:"type"`
	Path            string              `provider:"path"`
	URL             string              `provider:"url,omitempty"`
	URLProxy        bool                `provider:"url-proxy,omitempty"`
	Interval        time.Duration       `provider:"interval,omitempty"`
	Filter          string              `provider:"filter,omitempty"`
	HealthCheck     healthCheckSchema   `provider:"health-check,omitempty"`
	ForceCertVerify bool                `provider:"force-cert-verify,omitempty"`
	UDP             bool                `provider:"udp,omitempty"`
	DisableUDP      bool                `provider:"disable-udp,omitempty"`
	DisableDNS      bool                `provider:"disable-dns,omitempty"`
	RandomHost      bool                `provider:"rand-host,omitempty"`
	PrefixName      string              `provider:"prefix-name,omitempty"`
	Header          map[string][]string `provider:"header,omitempty"`
}

func ParseProxyProvider(name string, mapping map[string]any, _ bool) (types.ProxyProvider, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})

	globalForceCertVerify := true
	schema := &proxyProviderSchema{
		ForceCertVerify: globalForceCertVerify,
		HealthCheck: healthCheckSchema{
			Lazy: true,
		},
	}

	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, err
	}

	var hcInterval time.Duration
	if schema.HealthCheck.Enable {
		hcInterval = schema.HealthCheck.Interval
	}
	hc := NewHealthCheck([]C.Proxy{}, schema.HealthCheck.URL, hcInterval, schema.HealthCheck.Lazy)

	vehicle, err := newVehicle(schema)
	if err != nil {
		return nil, err
	}

	interval := schema.Interval
	filter := schema.Filter
	option := adapter.ProxyOption{
		ForceCertVerify: schema.ForceCertVerify,
		ForceUDP:        schema.UDP,
		DisableUDP:      schema.DisableUDP,
		DisableDNS:      schema.DisableDNS,
		RandomHost:      schema.RandomHost,
		PrefixName:      schema.PrefixName,
		AutoCipher:      true,
	}
	return NewProxySetProvider(name, interval, filter, vehicle, hc, globalForceCertVerify, option)
}

func newVehicle(schema *proxyProviderSchema) (types.Vehicle, error) {
	path := C.Path.Resolve(schema.Path)

	switch schema.Type {
	case "file":
		return NewFileVehicle(path), nil
	case "http":
		if !C.Path.IsSubHomeDir(path) {
			return nil, errors.New("the path is not a sub path of home directory")
		}

		if schema.Header == nil {
			schema.Header = map[string][]string{
				"User-Agent": {"ClashPlusPro/" + C.Version},
			}
		} else if _, ok := schema.Header["User-Agent"]; !ok {
			schema.Header["User-Agent"] = []string{"ClashPlusPro/" + C.Version}
		}

		return NewHTTPVehicle(path, schema.URL, schema.URLProxy, schema.Header), nil
	default:
		return nil, fmt.Errorf("%w: %s", errVehicleType, schema.Type)
	}
}
