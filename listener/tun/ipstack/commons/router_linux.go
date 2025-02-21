package commons

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

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
	if !addr4.IsValid() {
		return fmt.Errorf("invalid tun address4: %s", addr4)
	}
	if !addr6.IsValid() {
		return fmt.Errorf("invalid tun address6: %s", addr6)
	}

	devInterface, err := netlink.LinkByName(dev.Name())
	if err != nil {
		return err
	}

	if err = netlink.LinkSetUp(devInterface); err != nil {
		return err
	}

	ip4 := GetFirstAvailableIP(addr4)
	ip6 := GetFirstAvailableIP(addr6)

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
		return fmt.Errorf("failed to add tun ipv4 address: %w", err)
	}

	if autoRoute {
		if err = configInterfaceRouting(devInterface.Attrs().Index, ip4, defaultRoutes); err != nil { // route 4
			return fmt.Errorf("failed to add tun ipv4 route: %w", err)
		}
	}

	// it will set to true by eBPF, currently the eBPF feature only supports ipv4.
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
		return fmt.Errorf("failed to add tun ipv6 address: %w", err)
	}

	if autoRoute {
		if err = configInterfaceRouting(devInterface.Attrs().Index, ip6, defaultRoutes6); err != nil { // route 6
			return fmt.Errorf("failed to add tun ipv6 route: %w", err)
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
			Src:       linkAddr.AsSlice(),
			Dst:       dst,
			Table:     unix.RT_TABLE_MAIN,
			Scope:     unix.RT_SCOPE_LINK,
			Protocol:  unix.RTPROT_KERNEL,
			LinkIndex: interfaceIndex,
			Priority:  100,
		}

		if err := netlink.RouteAdd(rt); err != nil {
			return err
		}
	}

	return nil
}

func defaultRouteInterface() (*DefaultInterface, error) {
	routes, err := netlink.RouteListFiltered(unix.AF_UNSPEC, &netlink.Route{Dst: nil}, netlink.RT_FILTER_DST)
	if err != nil {
		return nil, err
	}

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
