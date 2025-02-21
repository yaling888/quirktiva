package commons

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/phuslu/log"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/yaling888/quirktiva/common/nnip"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/device"
	"github.com/yaling888/quirktiva/listener/tun/device/tun"
)

var (
	wintunInterfaceName          string
	unicastAddressChangeCallback *winipcfg.UnicastAddressChangeCallback
	unicastAddressChangeLock     sync.Mutex
)

func ConfigInterfaceAddress(dev device.Device, addr4, addr6 netip.Prefix, forceMTU int, autoRoute bool) error {
	if !addr4.IsValid() {
		return fmt.Errorf("invalid tun address4: %s", addr4)
	}
	if !addr6.IsValid() {
		return fmt.Errorf("invalid tun address6: %s", addr6)
	}

	retryOnFailure := services.StartedAtBoot()
	tryTimes := 0
	var err error
startOver:
	if tryTimes > 0 {
		log.Info().
			Err(err).
			Dur("time", windows.DurationSinceBoot()).
			Msg("[TUN] retrying interface configuration after failure, because system just booted")
		time.Sleep(time.Second)
		retryOnFailure = retryOnFailure && tryTimes < 15
	}
	tryTimes++

	ip4 := GetFirstAvailableIP(addr4)
	gw4 := ip4.Next()

	ip6 := GetFirstAvailableIP(addr6)
	gw6 := ip6.Next()

	luid := winipcfg.LUID(dev.(*tun.TUN).LUID())

	err = luid.FlushDNS(windows.AF_INET)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to flush DNS4: %w", err)
	}
	err = luid.FlushDNS(windows.AF_INET6)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to flush DNS6: %w", err)
	}

	foundDefault4 := false
	foundDefault6 := false

	if autoRoute {
		var routes4, routes6 []*winipcfg.RouteData

		for _, r := range defaultRoutes {
			p := netip.MustParsePrefix(r)
			route := &winipcfg.RouteData{
				Destination: p.Masked(),
				NextHop:     gw4,
				Metric:      100,
			}
			if p.Bits() == 0 {
				foundDefault4 = true
				route.NextHop = netip.IPv4Unspecified()
				route.Metric = 0
			}
			routes4 = append(routes4, route)
		}

		for _, r := range defaultRoutes6 {
			p := netip.MustParsePrefix(r)
			route := &winipcfg.RouteData{
				Destination: p.Masked(),
				NextHop:     gw6,
				Metric:      100,
			}
			if p.Bits() == 0 {
				foundDefault6 = true
				route.NextHop = netip.IPv6Unspecified()
				route.Metric = 0
			}
			routes6 = append(routes6, route)
		}

		// add gateway
		routes4 = append(routes4, &winipcfg.RouteData{
			Destination: addr4.Masked(),
			NextHop:     gw4,
			Metric:      0,
		})
		routes6 = append(routes6, &winipcfg.RouteData{
			Destination: addr6.Masked(),
			NextHop:     gw6,
			Metric:      0,
		})

		err = luid.SetRoutesForFamily(windows.AF_INET, routes4)
		if err == windows.ERROR_NOT_FOUND && retryOnFailure {
			goto startOver
		} else if err != nil {
			return fmt.Errorf("unable to set route4: %w", err)
		}

		err = luid.SetRoutesForFamily(windows.AF_INET6, routes6)
		if err == windows.ERROR_NOT_FOUND && retryOnFailure {
			goto startOver
		} else if err != nil {
			return fmt.Errorf("unable to set route6: %w", err)
		}
	}

	address4 := []netip.Prefix{netip.PrefixFrom(ip4, addr4.Bits())}
	err = luid.SetIPAddressesForFamily(windows.AF_INET, address4)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(windows.AF_INET, address4)
		err = luid.SetIPAddressesForFamily(windows.AF_INET, address4)
	}
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set ipv4: %w", err)
	}

	address6 := []netip.Prefix{netip.PrefixFrom(ip6, addr6.Bits())}
	err = luid.SetIPAddressesForFamily(windows.AF_INET6, address6)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(windows.AF_INET6, address6)
		err = luid.SetIPAddressesForFamily(windows.AF_INET6, address6)
	}
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set ipv6: %w", err)
	}

	var ipif *winipcfg.MibIPInterfaceRow
	ipif, err = luid.IPInterface(windows.AF_INET)
	if err != nil {
		return err
	}
	ipif.ForwardingEnabled = true
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif.DadTransmits = 0
	ipif.ManagedAddressConfigurationSupported = false
	ipif.OtherStatefulConfigurationSupported = false
	if forceMTU > 0 {
		ipif.NLMTU = uint32(forceMTU)
	}
	if foundDefault4 {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	err = ipif.Set()
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set v4 metric and MTU: %w", err)
	}

	var ipif6 *winipcfg.MibIPInterfaceRow
	ipif6, err = luid.IPInterface(windows.AF_INET6)
	if err != nil {
		return err
	}
	ipif6.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif6.DadTransmits = 0
	ipif6.ManagedAddressConfigurationSupported = false
	ipif6.OtherStatefulConfigurationSupported = false
	if forceMTU > 0 {
		ipif6.NLMTU = uint32(forceMTU)
	}
	if foundDefault6 {
		ipif6.UseAutomaticMetric = false
		ipif6.Metric = 0
	}
	err = ipif6.Set()
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set v6 metric and MTU: %w", err)
	}

	err = luid.SetDNS(windows.AF_INET, []netip.Addr{gw4}, nil)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set DNS4 %s %s: %w", gw4, "nil", err)
	}

	err = luid.SetDNS(windows.AF_INET6, []netip.Addr{gw6}, nil)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set DNS6 %s %s: %w", gw6, "nil", err)
	}

	wintunInterfaceName = dev.Name()

	return nil
}

func StartDefaultInterfaceChangeMonitor() {
	monitorMux.Lock()
	defer monitorMux.Unlock()

	if unicastAddressChangeCallback != nil {
		return
	}

	var err error
	unicastAddressChangeCallback, err = winipcfg.RegisterUnicastAddressChangeCallback(unicastAddressChange)
	if err != nil {
		log.Error().Err(err).Msg("[Route] register uni-cast address change callback failed")
		return
	}

	tunStatus = C.TunEnabled

	log.Info().Msg("[Route] register uni-cast address change callback")
}

func StopDefaultInterfaceChangeMonitor() {
	monitorMux.Lock()
	defer monitorMux.Unlock()

	if unicastAddressChangeCallback == nil || tunStatus == C.TunPaused {
		return
	}

	_ = unicastAddressChangeCallback.Unregister()
	unicastAddressChangeCallback = nil
	tunChangeCallback = nil
	tunStatus = C.TunDisabled
}

func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []netip.Prefix) {
	if len(addresses) == 0 {
		return
	}
	addrHash := make(map[netip.Addr]bool, len(addresses))
	for i := range addresses {
		addrHash[addresses[i].Addr()] = true
	}
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, ifaceM := range interfaces {
		if ifaceM.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for address := ifaceM.FirstUnicastAddress; address != nil; address = address.Next {
			if ip := nnip.IpToAddr(address.Address.IP()); addrHash[ip] {
				prefix := netip.PrefixFrom(ip, int(address.OnLinkPrefixLength))
				log.Info().
					Str("address", prefix.String()).
					Str("interface", ifaceM.FriendlyName()).
					Msg("[TUN] cleaning up stale")
				_ = ifaceM.LUID.DeleteIPAddress(prefix)
			}
		}
	}
}

func defaultRouteInterface() (*DefaultInterface, error) {
	ifaceM, err := getAutoDetectInterfaceByFamily(winipcfg.AddressFamily(windows.AF_INET))
	if err == nil {
		return ifaceM, err
	}

	return getAutoDetectInterfaceByFamily(winipcfg.AddressFamily(windows.AF_INET6))
}

func getAutoDetectInterfaceByFamily(family winipcfg.AddressFamily) (*DefaultInterface, error) {
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return nil, err
	}

	var destination netip.Prefix
	if family == windows.AF_INET {
		destination = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	} else {
		destination = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}

	for _, ifaceM := range interfaces {
		if ifaceM.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		ifname := ifaceM.FriendlyName()

		if wintunInterfaceName == ifname || ifaceM.FirstUnicastAddress == nil {
			continue
		}

		for gatewayAddress := ifaceM.FirstGatewayAddress; gatewayAddress != nil; gatewayAddress = gatewayAddress.Next {
			nextHop := nnip.IpToAddr(gatewayAddress.Address.IP())

			if _, err = ifaceM.LUID.Route(destination, nextHop); err == nil {
				return &DefaultInterface{
					Name:    ifname,
					Index:   int(ifaceM.IfIndex),
					IP:      nnip.IpToAddr(ifaceM.FirstUnicastAddress.Address.IP()),
					Gateway: nextHop,
				}, nil
			}
		}
	}

	return nil, errInterfaceNotFound
}

func unicastAddressChange(_ winipcfg.MibNotificationType, _ *winipcfg.MibUnicastIPAddressRow) {
	unicastAddressChangeLock.Lock()
	defer unicastAddressChangeLock.Unlock()

	onChangeDefaultRoute()
}
