package commons

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/phuslu/log"

	A "github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/tunnel"
)

//nolint:unused
var (
	defaultRoutes = []string{
		"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5",
		"16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
	}

	monitorMux sync.Mutex

	tunStatus            = C.TunDisabled
	tunChangeCallback    C.TUNChangeCallback
	errInterfaceNotFound = errors.New("default interface not found")
)

type DefaultInterface struct {
	Name    string
	Index   int
	IP      netip.Addr
	Gateway netip.Addr
}

func GetAutoDetectInterface() (string, error) {
	var (
		retryOnFailure = true
		tryTimes       = 0
	)
startOver:
	if tryTimes > 0 {
		log.Info().
			Int("times", tryTimes).
			Msg("[TUN] retrying lookup default interface after failure, maybe system just booted")
		time.Sleep(time.Second)
		retryOnFailure = retryOnFailure && tryTimes < 25
	}
	tryTimes++

	ifaceM, err := defaultRouteInterface()
	if err != nil {
		if err == errInterfaceNotFound && retryOnFailure {
			goto startOver
		} else {
			return "", err
		}
	}

	return ifaceM.Name, nil
}

func UpdateWireGuardBind() {
	ps := tunnel.Proxies()
	for _, p := range ps {
		if p.Type() == C.WireGuard {
			p.(*A.Proxy).ProxyAdapter.(*outbound.WireGuard).UpdateBind()
		}
	}
	pds := tunnel.Providers()
	for _, pd := range pds {
		if pd.VehicleType() == provider.Compatible {
			continue
		}
		for _, p := range pd.Proxies() {
			if p.Type() == C.WireGuard {
				p.(*A.Proxy).ProxyAdapter.(*outbound.WireGuard).UpdateBind()
			}
		}
	}
}

func SetTunChangeCallback(callback C.TUNChangeCallback) {
	tunChangeCallback = callback
}

func SetTunStatus(status C.TUNState) {
	tunStatus = status
}

//nolint:unused
func onChangeDefaultRoute() {
	routeInterface, err := defaultRouteInterface()
	if err != nil {
		if err == errInterfaceNotFound && tunStatus == C.TunEnabled {
			log.Info().Msg("[Route] lost default interface, pause tun adapter")

			tunStatus = C.TunPaused
			tunChangeCallback.Pause()
		}
		return
	}

	interfaceName := routeInterface.Name
	oldInterfaceName := dialer.DefaultInterface.Load()
	if interfaceName == oldInterfaceName && tunStatus == C.TunEnabled {
		return
	}

	dialer.DefaultInterface.Store(interfaceName)

	iface.FlushCache()
	UpdateWireGuardBind()

	if tunStatus == C.TunPaused {
		log.Info().
			Str("iface", interfaceName).
			NetIPAddr("ip", routeInterface.IP).
			NetIPAddr("gw", routeInterface.Gateway).
			Msg("[Route] found default interface, resume tun adapter")

		tunStatus = C.TunEnabled
		tunChangeCallback.Resume()
		return
	}

	log.Info().
		Str("oldIface", oldInterfaceName).
		Str("newIface", interfaceName).
		NetIPAddr("ip", routeInterface.IP).
		NetIPAddr("gw", routeInterface.Gateway).
		Msg("[Route] default interface changed")
}
