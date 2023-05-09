package adapter

import (
	"fmt"

	"github.com/phuslu/log"

	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/structure"
	C "github.com/Dreamacro/clash/constant"
)

func ParseProxy(mapping map[string]any, forceCertVerify, udp, autoCipher, randomHost bool) (C.Proxy, error) {
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
		ssOption := &outbound.ShadowSocksOption{}
		err = decoder.Decode(mapping, ssOption)
		if err != nil {
			break
		}
		if udp {
			ssOption.UDP = true
		}
		if randomHost {
			ssOption.RandomHost = true
		}
		proxy, err = outbound.NewShadowSocks(*ssOption)
	case "ssr":
		ssrOption := &outbound.ShadowSocksROption{}
		err = decoder.Decode(mapping, ssrOption)
		if err != nil {
			break
		}
		if udp {
			ssrOption.UDP = true
		}
		if randomHost {
			ssrOption.RandomHost = true
		}
		proxy, err = outbound.NewShadowSocksR(*ssrOption)
	case "socks5":
		socksOption := &outbound.Socks5Option{}
		err = decoder.Decode(mapping, socksOption)
		if err != nil {
			break
		}
		if forceCertVerify {
			socksOption.SkipCertVerify = false
		}
		if udp {
			socksOption.UDP = true
		}
		proxy = outbound.NewSocks5(*socksOption)
	case "http":
		httpOption := &outbound.HttpOption{}
		err = decoder.Decode(mapping, httpOption)
		if err != nil {
			break
		}
		if forceCertVerify {
			httpOption.SkipCertVerify = false
		}
		proxy = outbound.NewHttp(*httpOption)
	case "vmess":
		vmessOption := &outbound.VmessOption{
			HTTPOpts: outbound.HTTPOptions{
				Method:  "GET",
				Path:    []string{"/"},
				Headers: make(map[string][]string),
			},
		}
		err = decoder.Decode(mapping, vmessOption)
		if err != nil {
			break
		}
		if forceCertVerify {
			vmessOption.SkipCertVerify = false
		}
		if udp {
			vmessOption.UDP = true
		}
		if autoCipher {
			vmessOption.Cipher = "auto"
		}
		if randomHost {
			vmessOption.RandomHost = true
		}
		proxy, err = outbound.NewVmess(*vmessOption)
	case "vless":
		vlessOption := &outbound.VlessOption{}
		err = decoder.Decode(mapping, vlessOption)
		if err != nil {
			break
		}
		if forceCertVerify {
			vlessOption.SkipCertVerify = false
		}
		if udp {
			vlessOption.UDP = true
		}
		log.Warn().Str("name", vlessOption.Name).Msg("[Config] proxy type VLESS is deprecated")
		proxy, err = outbound.NewVless(*vlessOption)
	case "snell":
		snellOption := &outbound.SnellOption{}
		err = decoder.Decode(mapping, snellOption)
		if err != nil {
			break
		}
		if udp {
			snellOption.UDP = true
		}
		if randomHost {
			snellOption.RandomHost = true
		}
		proxy, err = outbound.NewSnell(*snellOption)
	case "trojan":
		trojanOption := &outbound.TrojanOption{}
		err = decoder.Decode(mapping, trojanOption)
		if err != nil {
			break
		}
		if forceCertVerify {
			trojanOption.SkipCertVerify = false
		}
		if udp {
			trojanOption.UDP = true
		}
		if trojanOption.Flow != "" {
			log.Warn().Str("proxy", trojanOption.Name).Msg("[Config] trojan xTLS is deprecated")
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
		if udp {
			wireguardOption.UDP = true
		}
		proxy, err = outbound.NewWireGuard(*wireguardOption)
	default:
		return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
	}

	if err != nil {
		return nil, err
	}

	return NewProxy(proxy), nil
}
