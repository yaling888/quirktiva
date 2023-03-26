package commons

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/phuslu/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/Dreamacro/clash/common/nnip"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/tun/device"
)

var (
	routeCtx       context.Context
	routeCancel    context.CancelFunc
	routeChangeMux sync.Mutex
)

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
	if !autoRoute {
		ones = bits
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
		log.Error().Err(err).Msg("[Route] subscribe to route event notifications failed")
		return
	}

	tunStatus = C.TunEnabled

	log.Info().Msg("[Route] subscribe to route event notifications")

	go func() {
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
	}()
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
			link, err1 := netlink.LinkByIndex(route.LinkIndex)
			if err1 != nil {
				return nil, err1
			}

			if link.Type() != "device" && link.Type() != "bridge" && link.Type() != "veth" {
				continue
			}

			ip := route.Src
			if ip == nil {
				addrs, err2 := netlink.AddrList(link, unix.AF_INET)
				if err2 != nil {
					return nil, err2
				}
				if len(addrs) == 0 {
					continue
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

	onChangeDefaultRoute()
}
