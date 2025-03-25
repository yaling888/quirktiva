package commons

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/phuslu/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/yaling888/quirktiva/common/nnip"
	"github.com/yaling888/quirktiva/component/resolver"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/device"
)

var (
	routeCtx       context.Context
	routeCancel    context.CancelFunc
	routeChangeMux sync.Mutex
)

func ConfigInterfaceAddress(dev device.Device, addr4, addr6 netip.Prefix, _ int, autoRoute bool) error {
	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		return err
	}

	if err = netlink.LinkSetUp(link); err != nil {
		return err
	}

	return ConfigInterfaceAddressAndRoutes(link, addr4, addr6, autoRoute, false)
}

func ConfigInterfaceAddressAndRoutes(devInterface netlink.Link, addr4, addr6 netip.Prefix, autoRoute, nextIP bool) (err error) {
	if !addr4.IsValid() {
		addr4 = DefaultPrefix4
	}
	if !addr6.IsValid() {
		addr6 = DefaultPrefix6
	}

	if (devInterface.Attrs().Flags & net.FlagUp) == 0 {
		if err = netlink.LinkSetUp(devInterface); err != nil {
			return fmt.Errorf("failed to set interface up, iface: %s, error: %w", devInterface.Attrs().Name, err)
		}
	}

	ip4 := GetFirstAvailableIP(addr4)
	ip6 := GetFirstAvailableIP(addr6)

	if nextIP {
		ip4 = ip4.Next()
		ip6 = ip6.Next()
	}

	bits4 := ip4.BitLen()
	ones4 := addr4.Bits()
	bits6 := ip6.BitLen()
	ones6 := addr6.Bits()
	if !autoRoute {
		ones4 = bits4
		ones6 = bits6
	}

	address4 := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip4.AsSlice(),
			Mask: net.CIDRMask(ones4, bits4),
		},
	}

	if err = netlink.AddrAdd(devInterface, address4); err != nil {
		return fmt.Errorf("failed to add ipv4 address, iface: %s, error: %w", devInterface.Attrs().Name, err)
	}

	if autoRoute {
		if err = configInterfaceRouting(devInterface.Attrs().Index, ip4, defaultRoutes); err != nil { // route 4
			return fmt.Errorf("failed to add ipv4 route, iface: %s, error: %w", devInterface.Attrs().Name, err)
		}
	}

	if resolver.DisableIPv6 {
		return nil
	}

	address6 := &netlink.Addr{
		Scope: unix.RT_SCOPE_UNIVERSE,
		IPNet: &net.IPNet{
			IP:   ip6.AsSlice(),
			Mask: net.CIDRMask(ones6, bits6),
		},
	}

	if err = netlink.AddrAdd(devInterface, address6); err != nil {
		return fmt.Errorf("failed to add ipv6 address, iface: %s, error: %w", devInterface.Attrs().Name, err)
	}

	if autoRoute {
		if err = configInterfaceRouting(devInterface.Attrs().Index, ip6, defaultRoutes6); err != nil { // route 6
			return fmt.Errorf("failed to add ipv6 route, iface: %s, error: %w", devInterface.Attrs().Name, err)
		}
	}
	return nil
}

func StartDefaultInterfaceChangeMonitor() {
	monitorMux.Lock()
	defer monitorMux.Unlock()

	if routeCancel != nil {
		return
	}

	routeCtx, routeCancel = context.WithCancel(context.Background())

	routeChan := make(chan netlink.RouteUpdate)
	closeChan := make(chan struct{})

	if err := netlink.RouteSubscribe(routeChan, closeChan); err != nil {
		routeCancel()
		routeCancel = nil
		routeCtx = nil
		log.Error().Err(err).Msg("[Route] subscribe to route event notifications failed")
		return
	}

	done := routeCtx
	tunStatus = C.TunEnabled

	log.Info().Msg("[Route] subscribe to route event notifications")

	go func() {
		for {
			select {
			case update := <-routeChan:
				defaultRouteChangeCallback(update)
			case <-done.Done():
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

func configInterfaceRouting(interfaceIndex int, linkAddr netip.Addr, routes []string) error {
	for _, route := range routes {
		_, dst, _ := net.ParseCIDR(route)
		rt := &netlink.Route{
			Dst:       dst,
			Table:     unix.RT_TABLE_MAIN,
			Scope:     unix.RT_SCOPE_LINK,
			Protocol:  unix.RTPROT_KERNEL,
			LinkIndex: interfaceIndex,
			Priority:  100,
		}

		if linkAddr.Is4() {
			rt.Src = linkAddr.AsSlice()
		} else {
			rt.Type = unix.RTN_UNICAST
			rt.Scope = unix.RT_SCOPE_UNIVERSE
			rt.Priority = 256
		}

		delay := 10 * time.Millisecond
		tryTimes := 0

	retry:
		if err := netlink.RouteAdd(rt); err != nil {
			if err == unix.EINVAL && tryTimes < 5 { // retry add route 6 for invalid argument
				time.Sleep(delay)
				delay *= 2
				tryTimes++
				goto retry
			}
			return fmt.Errorf("route %s: %w", route, err)
		}
	}

	return nil
}

func defaultRouteInterface() (*DefaultInterface, error) {
	routes, err := netlink.RouteListFiltered(unix.AF_INET, &netlink.Route{Dst: nil}, netlink.RT_FILTER_DST)
	if err != nil {
		return nil, err
	}
	routes6, err := netlink.RouteListFiltered(unix.AF_INET6, &netlink.Route{Dst: nil}, netlink.RT_FILTER_DST)
	if err != nil {
		return nil, err
	}
	routes = append(routes, routes6...)
	for _, route := range routes {
		if route.Family != unix.AF_INET && route.Family != unix.AF_INET6 {
			continue
		}
		if route.LinkIndex == 0 || route.Gw == nil {
			continue
		}

		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			return nil, err
		}

		if link.Type() != "device" && link.Type() != "bridge" && link.Type() != "veth" {
			continue
		}

		ip := route.Src
		if ip == nil {
			addrs, err := netlink.AddrList(link, route.Family)
			if err != nil {
				return nil, err
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

	return nil, errInterfaceNotFound
}

func defaultRouteChangeCallback(update netlink.RouteUpdate) {
	routeChangeMux.Lock()
	defer routeChangeMux.Unlock()

	route := update.Route
	if (route.Family != unix.AF_INET && route.Family != unix.AF_INET6) || route.Dst != nil || route.Gw == nil {
		return
	}

	onChangeDefaultRoute()
}
