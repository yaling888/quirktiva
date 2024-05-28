package adapter

import (
	"fmt"
	"strings"

	"github.com/yaling888/quirktiva/adapter/outbound"
	"github.com/yaling888/quirktiva/common/structure"
	"github.com/yaling888/quirktiva/common/util"
	C "github.com/yaling888/quirktiva/constant"
)

type ProxyOption struct {
	ForceCertVerify bool
	ForceUDP        bool
	DisableUDP      bool
	DisableDNS      bool
	AutoCipher      bool
	RandomHost      bool
	PrefixName      string
}

func ParseProxy(mapping map[string]any, option ProxyOption) (C.Proxy, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	proxyType, existType := mapping["type"].(string)
	if !existType {
		return nil, fmt.Errorf("missing type")
	}

	var (
		proxy C.ProxyAdapter
		err   error
	)
	switch proxyType {
	case "ss":
		ssOption := &outbound.ShadowSocksOption{RemoteDnsResolve: true}
		err = decoder.Decode(mapping, ssOption)
		if err != nil {
			break
		}
		if option.ForceUDP {
			ssOption.UDP = true
		}
		if option.DisableUDP {
			ssOption.UDP = false
		}
		if option.RandomHost {
			ssOption.RandomHost = true
		}
		if option.DisableDNS {
			ssOption.RemoteDnsResolve = false
		}
		proxy, err = outbound.NewShadowSocks(*ssOption)
	case "ssr":
		ssrOption := &outbound.ShadowSocksROption{RemoteDnsResolve: true}
		err = decoder.Decode(mapping, ssrOption)
		if err != nil {
			break
		}
		if option.ForceUDP {
			ssrOption.UDP = true
		}
		if option.DisableUDP {
			ssrOption.UDP = false
		}
		if option.RandomHost {
			ssrOption.RandomHost = true
		}
		if option.DisableDNS {
			ssrOption.RemoteDnsResolve = false
		}
		proxy, err = outbound.NewShadowSocksR(*ssrOption)
	case "socks5":
		socksOption := &outbound.Socks5Option{RemoteDnsResolve: true}
		err = decoder.Decode(mapping, socksOption)
		if err != nil {
			break
		}
		if option.ForceCertVerify {
			socksOption.SkipCertVerify = false
		}
		if option.ForceUDP {
			socksOption.UDP = true
		}
		if option.DisableDNS {
			socksOption.RemoteDnsResolve = false
		}
		proxy = outbound.NewSocks5(*socksOption)
	case "http":
		httpOption := &outbound.HttpOption{RemoteDnsResolve: true}
		err = decoder.Decode(mapping, httpOption)
		if err != nil {
			break
		}
		if option.ForceCertVerify {
			httpOption.SkipCertVerify = false
		}
		if option.DisableDNS {
			httpOption.RemoteDnsResolve = false
		}
		proxy = outbound.NewHttp(*httpOption)
	case "vmess":
		vmessOption := &outbound.VmessOption{
			HTTPOpts: outbound.HTTPOptions{
				Method:  "GET",
				Path:    []string{"/"},
				Headers: make(map[string][]string),
			},
			RemoteDnsResolve: true,
		}
		err = decoder.Decode(mapping, vmessOption)
		if err != nil {
			break
		}
		vmessOption.HTTPOpts.Method = util.EmptyOr(strings.ToUpper(vmessOption.HTTPOpts.Method), "GET")
		if option.ForceCertVerify {
			vmessOption.SkipCertVerify = false
		}
		if option.ForceUDP {
			vmessOption.UDP = true
		}
		if option.DisableUDP {
			vmessOption.UDP = false
		}
		if option.AutoCipher {
			vmessOption.Cipher = "auto"
		}
		if option.RandomHost {
			vmessOption.RandomHost = true
		}
		if option.DisableDNS {
			vmessOption.RemoteDnsResolve = false
		}
		proxy, err = outbound.NewVmess(*vmessOption)
	case "vless":
		vlessOption := &outbound.VlessOption{
			HTTPOpts: outbound.HTTPOptions{
				Method:  "GET",
				Path:    []string{"/"},
				Headers: make(map[string][]string),
			},
			RemoteDnsResolve: true,
		}
		err = decoder.Decode(mapping, vlessOption)
		if err != nil {
			break
		}
		vlessOption.HTTPOpts.Method = util.EmptyOr(strings.ToUpper(vlessOption.HTTPOpts.Method), "GET")
		if option.ForceCertVerify {
			vlessOption.SkipCertVerify = false
		}
		if option.ForceUDP {
			vlessOption.UDP = true
		}
		if option.DisableUDP {
			vlessOption.UDP = false
		}
		if option.DisableDNS {
			vlessOption.RemoteDnsResolve = false
		}
		if option.RandomHost {
			vlessOption.RandomHost = true
		}
		proxy, err = outbound.NewVless(*vlessOption)
	case "snell":
		snellOption := &outbound.SnellOption{RemoteDnsResolve: true}
		err = decoder.Decode(mapping, snellOption)
		if err != nil {
			break
		}
		if option.ForceUDP {
			snellOption.UDP = true
		}
		if option.DisableUDP {
			snellOption.UDP = false
		}
		if option.RandomHost {
			snellOption.RandomHost = true
		}
		if option.DisableDNS {
			snellOption.RemoteDnsResolve = false
		}
		proxy, err = outbound.NewSnell(*snellOption)
	case "trojan":
		trojanOption := &outbound.TrojanOption{RemoteDnsResolve: true}
		err = decoder.Decode(mapping, trojanOption)
		if err != nil {
			break
		}
		if option.ForceCertVerify {
			trojanOption.SkipCertVerify = false
		}
		if option.ForceUDP {
			trojanOption.UDP = true
		}
		if option.DisableUDP {
			trojanOption.UDP = false
		}
		if option.DisableDNS {
			trojanOption.RemoteDnsResolve = false
		}
		proxy, err = outbound.NewTrojan(*trojanOption)
	case "wireguard":
		wireguardOption := &outbound.WireGuardOption{
			RemoteDnsResolve: true,
		}
		err = decoder.Decode(mapping, wireguardOption)
		if err != nil {
			break
		}
		if option.ForceUDP {
			wireguardOption.UDP = true
		}
		proxy, err = outbound.NewWireGuard(*wireguardOption)
	case "hysteria2":
		hysteria2Option := &outbound.Hysteria2Option{
			RemoteDnsResolve: true,
		}
		err = decoder.Decode(mapping, hysteria2Option)
		if err != nil {
			break
		}
		if option.ForceCertVerify {
			hysteria2Option.SkipCertVerify = false
		}
		if option.ForceUDP {
			hysteria2Option.UDP = true
		}
		if option.DisableDNS {
			hysteria2Option.RemoteDnsResolve = false
		}
		proxy, err = outbound.NewHysteria2(*hysteria2Option)
	default:
		return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
	}

	if err != nil {
		return nil, err
	}

	return NewProxy(proxy), nil
}
