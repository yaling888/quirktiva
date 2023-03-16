//go:build freebsd || openbsd

package wireguard

import (
	"net/netip"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
)

func getListenIP(network string, interfaceName string) (string, error) {
	if interfaceName == "" {
		interfaceName = dialer.DefaultInterface.Load()
		if interfaceName == "" {
			return "", nil
		}
	}

	ifaceObj, err := iface.ResolveInterface(interfaceName)
	if err != nil {
		return "", err
	}

	var addr *netip.Prefix
	switch network {
	case "udp4":
		addr, err = ifaceObj.PickIPv4Addr(netip.Addr{})
	case "udp6":
		addr, err = ifaceObj.PickIPv6Addr(netip.Addr{})
	default:
		addr, err = ifaceObj.PickIPv4Addr(netip.Addr{})
	}
	if err != nil {
		return "", err
	}

	return addr.String(), nil
}
