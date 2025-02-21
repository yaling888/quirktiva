package commons

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/phuslu/log"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/device"
)

var (
	routeCtx       context.Context
	routeCancel    context.CancelFunc
	routeChangeMux sync.Mutex
	routeSubscribe *subscriber
)

func ConfigInterfaceAddress(dev device.Device, prefix4, prefix6 netip.Prefix, _ int, autoRoute bool) error {
	if !prefix4.IsValid() {
		return fmt.Errorf("invalid tun address4: %s", prefix4)
	}
	if !prefix6.IsValid() {
		return fmt.Errorf("invalid tun address6: %s", prefix6)
	}

	var (
		interfaceName = dev.Name()
		ip            = GetFirstAvailableIP(prefix4)
		gw            = ip.Next()
		mask, _       = netip.AddrFromSlice(net.CIDRMask(prefix4.Bits(), ip.BitLen()))
	)

	if err := setAddress(interfaceName, prefix4); err != nil {
		return err
	}
	if err := setAddress(interfaceName, prefix6); err != nil {
		return err
	}

	iff, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get tun index: %w", err)
	}
	linkAddr := &route.LinkAddr{
		Index: iff.Index,
		Name:  interfaceName,
	}

	routeSocket, err := socketCloexec(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("unable to create AF_ROUTE socket: %w", err)
	}
	defer func() {
		_ = unix.Shutdown(routeSocket, unix.SHUT_RDWR)
		_ = unix.Close(routeSocket)
	}()

	routeAddr := &route.Inet4Addr{IP: gw.As4()}
	maskAddr := &route.Inet4Addr{IP: mask.As4()}
	_ = addRoute(routeSocket, routeAddr, maskAddr, linkAddr, unix.RTF_HOST)

	if autoRoute {
		routes := defaultRoutes
		routes = append(routes, prefix4.String())
		routes = append(routes, defaultRoutes6...)
		for _, r := range routes {
			_, cidr, _ := net.ParseCIDR(r)
			if ip4, _ := netip.AddrFromSlice(cidr.IP); ip4.Is4() {
				ra := &route.Inet4Addr{IP: ip4.As4()}
				ma := &route.Inet4Addr{}
				copy(ma.IP[:], cidr.Mask)
				err = addRoute(routeSocket, ra, ma, linkAddr, 0)
			} else {
				ra := &route.Inet6Addr{}
				ma := &route.Inet6Addr{}
				copy(ra.IP[:], cidr.IP)
				copy(ma.IP[:], cidr.Mask)
				err = addRoute(routeSocket, ra, ma, linkAddr, 0)
			}
			if err != nil {
				if errors.Is(err, unix.EEXIST) {
					log.Warn().
						Str("route", r).
						Msg("[Stack] unable to add tun route, identical route already exists")
				} else {
					return err
				}
			}
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

	var (
		err       error
		routeChan = make(chan *route.RouteMessage, 5)
		closeChan = make(chan struct{})
	)

	routeSubscribe = &subscriber{
		ch:   routeChan,
		done: closeChan,
	}

	routeSubscribe.routeSocket, err = socketCloexec(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		routeCancel()
		routeSubscribe = nil
		routeCancel = nil
		routeCtx = nil
		log.Error().Err(err).Msg("[Route] subscribe to route event notifications failed")
		return
	}

	done := routeCtx
	tunStatus = C.TunEnabled

	go func() {
		for {
			select {
			case update := <-routeSubscribe.ch:
				go defaultRouteChangeCallback(update)
			case <-done.Done():
				close(closeChan)
				for range routeChan {
				}
				log.Info().Msg("[Route] unsubscribe route event notifications")
				return
			}
		}
	}()

	go routeSubscribe.routineRouteListener()

	log.Info().Msg("[Route] subscribe to route event notifications")
}

func StopDefaultInterfaceChangeMonitor() {
	monitorMux.Lock()
	defer monitorMux.Unlock()

	if routeCancel == nil || tunStatus == C.TunPaused {
		return
	}

	routeCancel()
	routeSubscribe.close()
	routeSubscribe = nil
	routeCancel = nil
	routeCtx = nil

	tunChangeCallback = nil
	tunStatus = C.TunDisabled
}

func defaultRouteInterface() (*DefaultInterface, error) {
	rib, err := route.FetchRIB(unix.AF_INET, unix.NET_RT_DUMP2, 0)
	if err != nil {
		return nil, fmt.Errorf("route.FetchRIB: %w", err)
	}
	rib6, err := route.FetchRIB(unix.AF_INET6, unix.NET_RT_DUMP2, 0)
	if err != nil {
		return nil, fmt.Errorf("route.FetchRIB: %w", err)
	}

	rib = append(rib, rib6...)
	msgs, err := route.ParseRIB(unix.NET_RT_IFLIST2, rib)
	if err != nil {
		return nil, fmt.Errorf("route.ParseRIB: %w", err)
	}

	for _, message := range msgs {
		routeMessage := message.(*route.RouteMessage)
		if ((routeMessage.Flags & unix.RTF_UP) == 0) || ((routeMessage.Flags & unix.RTF_GATEWAY) == 0) {
			continue
		}

		addresses := routeMessage.Addrs

		var via netip.Addr
		switch ra := addresses[0].(type) {
		case *route.Inet4Addr:
			if (routeMessage.Flags & unix.RTF_STATIC) == 0 {
				continue
			}
			via = netip.AddrFrom4(ra.IP)
		case *route.Inet6Addr:
			via = netip.AddrFrom16(ra.IP)
		default:
			continue
		}

		if !via.IsUnspecified() || len(addresses) < 2 {
			continue
		}

		var gw netip.Addr
		switch ra := addresses[1].(type) {
		case *route.Inet4Addr:
			gw = netip.AddrFrom4(ra.IP)
		case *route.Inet6Addr:
			gw = netip.AddrFrom16(ra.IP)
		}

		if via.Is4() && !gw.IsGlobalUnicast() {
			continue
		}

		ifaceM, err1 := retryInterfaceByIndex(routeMessage.Index)
		if err1 != nil {
			continue
		}

		if strings.HasPrefix(ifaceM.Name, "utun") {
			continue
		}

		addrs, err1 := ifaceM.Addrs()
		if err1 != nil || len(addrs) == 0 {
			continue
		}

		var ip netip.Addr
		for _, addr := range addrs {
			if a, ok := addr.(*net.IPNet); ok {
				ip, _ = netip.AddrFromSlice(a.IP)
				if ip = ip.Unmap(); ip.IsGlobalUnicast() && (ip.Is4() == gw.Is4() || ip.Is6() == gw.Is6()) {
					break
				}
			}
		}

		if !ip.IsValid() {
			continue
		}

		return &DefaultInterface{
			Name:    ifaceM.Name,
			Index:   routeMessage.Index,
			IP:      ip,
			Gateway: gw,
		}, nil
	}

	return nil, errInterfaceNotFound
}

func defaultRouteChangeCallback(msg *route.RouteMessage) {
	if len(msg.Addrs) == 0 {
		return
	}
	var via netip.Addr
	switch ra := msg.Addrs[0].(type) {
	case *route.Inet4Addr:
		via = netip.AddrFrom4(ra.IP)
	case *route.Inet6Addr:
		via = netip.AddrFrom16(ra.IP)
	}
	if !via.IsUnspecified() {
		return
	}
	routeChangeMux.Lock()
	onChangeDefaultRoute()
	routeChangeMux.Unlock()
}

func setAddress(interfaceName string, prefix netip.Prefix) error {
	var (
		ip      = GetFirstAvailableIP(prefix)
		gw      = ip.Next()
		mask, _ = netip.AddrFromSlice(net.CIDRMask(prefix.Bits(), ip.BitLen()))
	)

	family := unix.AF_INET
	if ip.Is6() {
		family = unix.AF_INET6
	}
	fd, err := socketCloexec(family, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		_ = unix.Close(fd)
	}()

	if family == unix.AF_INET {
		ifra := ifReq{
			Addr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   ip.As4(),
			},
		}
		copy(ifra.Name[:], interfaceName)

		if err = ioctlPtr(fd, unix.SIOCSIFADDR, unsafe.Pointer(&ifra)); err != nil {
			return fmt.Errorf("failed to set tun address: %w", err)
		}

		ifra.Addr.Addr = mask.As4()
		if err = ioctlPtr(fd, unix.SIOCSIFNETMASK, unsafe.Pointer(&ifra)); err != nil {
			return fmt.Errorf("failed to set tun netmask: %w", err)
		}

		ifra.Addr.Addr = gw.As4()
		if err = ioctlPtr(fd, unix.SIOCSIFDSTADDR, unsafe.Pointer(&ifra)); err != nil {
			return fmt.Errorf("failed to set tun destination address: %w", err)
		}
	} else {
		ifra := in6AliasReq{
			Addr: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   ip.As16(),
			},
			PrefixMask: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   mask.As16(),
			},
			Lifetime: in6AddrLifetime{
				VLTime: 0xffffffff,
				PLTime: 0xffffffff,
			},
		}
		if prefix.Bits() == gw.BitLen() {
			ifra.DstAddr = unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   gw.As16(),
			}
		}
		copy(ifra.Name[:], interfaceName)

		// the constant SIOCAIFADDR_IN6 is undefined by golang.org/x/sys/unix/zerrors_darwin_amd64.go
		// we need to calculate it, see https://github.com/apple/darwin-xnu/blob/main/bsd/netinet6/in6_var.h#L591
		//
		// #define SIOCAIFADDR_IN6         _IOW('i', 26, struct in6_aliasreq)
		// value is 0x8080691a on 64 bits system
		siocAIFAddrIn6 := iow('i', 26, uint(unsafe.Sizeof(in6AliasReq{})))

		if err = ioctlPtr(fd, siocAIFAddrIn6, unsafe.Pointer(&ifra)); err != nil {
			return fmt.Errorf("failed to set tun address v6: %w", err)
		}
	}
	return nil
}

func addRoute(sock int, addr, mask, link route.Addr, flag int) error {
	flags := unix.RTF_UP
	if flag != 0 {
		flags |= flag
	}
	if (flags & unix.RTF_HOST) == 0 {
		flags |= unix.RTF_STATIC
	}

	r := route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_ADD,
		Flags:   flags,
		Seq:     1,
		Addrs: []route.Addr{
			unix.RTAX_DST:     addr,
			unix.RTAX_NETMASK: mask,
			unix.RTAX_GATEWAY: link,
		},
	}

	data, err := r.Marshal()
	if err != nil {
		return fmt.Errorf("failed to create route.RouteMessage: %w", err)
	}
	_, err = unix.Write(sock, data[:])
	if err != nil {
		return fmt.Errorf("failed to write route.RouteMessage to socket: %w", err)
	}

	return nil
}

func retryInterfaceByIndex(index int) (iface *net.Interface, err error) {
	for i := 0; i < 20; i++ {
		iface, err = net.InterfaceByIndex(index)
		if err != nil && errors.Is(err, unix.ENOMEM) {
			time.Sleep(time.Duration(i) * time.Second / 3)
			continue
		}
		return iface, err
	}
	return nil, err
}

func socketCloexec(family, sotype, proto int) (fd int, err error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	fd, err = unix.Socket(family, sotype, proto)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	return
}

func ioc(inout, group, num, len uint) uint {
	return inout | ((len & 0x1fff) << 16) | (group << 8) | num
}

// func ior(group, num, len uint) uint {
// 	 return ioc(0x40000000, group, num, len)
// }

func iow(group, num, len uint) uint {
	return ioc(0x80000000, group, num, len)
}

// func iowr(group, num, len uint) uint {
//	 return ioc(0x80000000|0x40000000, group, num, len)
// }

//go:linkname ioctlPtr golang.org/x/sys/unix.ioctlPtr
func ioctlPtr(_ int, _ uint, _ unsafe.Pointer) (err error)

type ifReq struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
}

// see https://github.com/apple/darwin-xnu/blob/main/bsd/netinet6/in6_var.h#L368
type in6AliasReq struct {
	Name       [unix.IFNAMSIZ]byte
	Addr       unix.RawSockaddrInet6
	DstAddr    unix.RawSockaddrInet6
	PrefixMask unix.RawSockaddrInet6
	Flags      int32
	Lifetime   in6AddrLifetime
}

type in6AddrLifetime struct {
	Expire    time.Duration /* valid lifetime expiration time */
	Preferred time.Duration /* preferred lifetime expiration time */
	VLTime    uint32        /* valid lifetime */
	PLTime    uint32        /* prefix lifetime */
}

type subscriber struct {
	ch   chan *route.RouteMessage
	done <-chan struct{}

	routeSocket int
	closeOnce   sync.Once
}

func (s *subscriber) close() {
	s.closeOnce.Do(func() {
		if s.routeSocket != -1 {
			_ = unix.Shutdown(s.routeSocket, unix.SHUT_RDWR)
			_ = unix.Close(s.routeSocket)
		}
	})
}

func (s *subscriber) routineRouteListener() {
	if s.done != nil {
		go func(ss *subscriber) {
			<-ss.done
			ss.close()
		}(s)
	}

	defer close(s.ch)

	data := make([]byte, os.Getpagesize())
	for {
	retry:
		n, err := unix.Read(s.routeSocket, data)
		if err != nil {
			if errno, ok := err.(unix.Errno); ok && errno == unix.EINTR {
				goto retry
			}
			return
		}

		if n < 14 {
			continue
		}

		if data[3 /* type */] != unix.RTM_ADD && data[3] != unix.RTM_DELETE {
			continue
		}

		msgs, err := route.ParseRIB(route.RIBTypeRoute, data[:n])
		if err != nil {
			continue
		}

		var msg *route.RouteMessage
		for _, message := range msgs {
			m := message.(*route.RouteMessage)
			if (m.Flags & unix.RTF_GATEWAY) != 0 {
				msg = m
				break
			}
		}

		if msg == nil {
			continue
		}

		s.ch <- msg
	}
}
