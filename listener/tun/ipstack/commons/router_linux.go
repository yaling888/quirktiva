package commons

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/Dreamacro/clash/common/nnip"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/log"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	routeCtx       context.Context
	routeCancel    context.CancelFunc
	routeChangeMux sync.Mutex
)

func GetAutoDetectInterface() (string, error) {
	ifaceM, err := defaultRouteInterface()
	if err != nil {
		return "", err
	}
	return ifaceM.Name, nil
}

func ConfigInterfaceAddress(dev device.Device, addr netip.Prefix, _ int, autoRoute bool) error {
	var (
		interfaceName = dev.Name()
		ip            = addr.Masked().Addr().Next()
	)

	devInterface, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return err
	}

	bits := ip.BitLen()
	ones := addr.Bits()
	if bits > 32 {
		ones += 96
	}

	address := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip.AsSlice(),
			Mask: net.CIDRMask(ones, bits),
		},
	}

	if err = netlink.LinkSetUp(devInterface); err != nil {
		return err
	}

	if err = netlink.AddrAdd(devInterface, address); err != nil {
		return err
	}

	if autoRoute {
		err = configInterfaceRouting(devInterface.Attrs().Index, addr)
	}
	return err
}

func configInterfaceRouting(interfaceIndex int, addr netip.Prefix) error {
	linkIP := addr.Masked().Addr().Next().AsSlice()
	for _, route := range defaultRoutes {
		_, dst, _ := net.ParseCIDR(route)
		rt := &netlink.Route{
			Src:       linkIP,
			Dst:       dst,
			Table:     unix.RT_TABLE_MAIN,
			Scope:     unix.RT_SCOPE_LINK,
			Protocol:  unix.RTPROT_KERNEL,
			LinkIndex: interfaceIndex,
		}

		if err := netlink.RouteAdd(rt); err != nil {
			return err
		}
	}

	return nil
}

func defaultRouteInterface() (*DefaultInterface, error) {
	routes, err := netlink.RouteListFiltered(unix.AF_INET, &netlink.Route{Dst: nil}, netlink.RT_FILTER_DST)
	if err != nil {
		return nil, err
	}

	for _, route := range routes {
		if route.LinkIndex != 0 && route.Gw != nil {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return nil, err
			}

			if link.Type() != "device" && link.Type() != "bridge" && link.Type() != "veth" {
				continue
			}

			ip := route.Src
			if ip == nil {
				addrs, err := netlink.AddrList(link, unix.AF_INET)
				if err != nil {
					return nil, err
				}
				if len(addrs) == 0 {
					return nil, fmt.Errorf("interface address not found")
				}
				ip = addrs[0].IP
			}

			return &DefaultInterface{
				Name:    link.Attrs().Name,
				Index:   route.LinkIndex,
				IP:      nnip.IpToAddr(ip),
				Gateway: nnip.IpToAddr(route.Gw),
			}, nil
		}
	}

	return nil, errInterfaceNotFound
}

func defaultRouteChangeCallback(update netlink.RouteUpdate) {
	routeChangeMux.Lock()
	defer routeChangeMux.Unlock()

	route := update.Route
	if route.Family != unix.AF_INET || route.Dst != nil || route.Gw == nil {
		return
	}

	routeInterface, err := defaultRouteInterface()
	if err != nil {
		if err == errInterfaceNotFound && tunStatus == C.TunEnabled {
			log.Warnln("[TUN] lost the default interface, pause tun adapter")

			tunStatus = C.TunPaused
			tunChangeCallback.Pause()
		}
		return
	}

	ifaceM, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		log.Warnln("[TUN] default interface monitor err: %v", err)
		return
	}

	interfaceName := routeInterface.Name

	if ifaceM.Attrs().Name != interfaceName {
		return
	}

	dialer.DefaultInterface.Store(interfaceName)

	iface.FlushCache()

	if tunStatus == C.TunPaused {
		log.Warnln("[TUN] found interface %s(%s), resume tun adapter", interfaceName, routeInterface.IP)

		tunStatus = C.TunEnabled
		tunChangeCallback.Resume()
		return
	}

	log.Warnln("[TUN] default interface changed to %s(%s) by monitor", interfaceName, routeInterface.IP)
}

func StartDefaultInterfaceChangeMonitor() {
	monitorMux.Lock()
	if routeCancel != nil {
		monitorMux.Unlock()
		return
	}

	routeCtx, routeCancel = context.WithCancel(context.Background())
	monitorMux.Unlock()

	routeChan := make(chan netlink.RouteUpdate)
	closeChan := make(chan struct{})

	if err := netlink.RouteSubscribe(routeChan, closeChan); err != nil {
		routeCancel()
		routeCancel = nil
		routeCtx = nil

		log.Errorln("[TUN] subscribe route change notifications failed: %v", err)
		return
	}

	tunStatus = C.TunEnabled

	log.Infoln("[TUN] subscribe route change notifications")

	for {
		select {
		case update := <-routeChan:
			defaultRouteChangeCallback(update)
		case <-routeCtx.Done():
			close(closeChan)
			for range routeChan {
			}
			return
		}
	}
}

func StopDefaultInterfaceChangeMonitor() {
	monitorMux.Lock()
	defer monitorMux.Unlock()

	if routeCancel == nil || tunStatus == C.TunPaused {
		return
	}

	routeCancel()
	routeCancel = nil
	routeCtx = nil

	tunChangeCallback = nil
	tunStatus = C.TunDisabled
}
