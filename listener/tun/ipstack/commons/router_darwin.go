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

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/tun/device"
)

var (
	routeCtx       context.Context
	routeCancel    context.CancelFunc
	routeChangeMux sync.Mutex
	routeSubscribe *subscriber
)

func ConfigInterfaceAddress(dev device.Device, prefix netip.Prefix, _ int, autoRoute bool) error {
	if !prefix.Addr().Is4() {
		return fmt.Errorf("supported ipv4 only")
	}

	var (
		interfaceName = dev.Name()
		ip            = prefix.Masked().Addr().Next()
		gw            = ip.Next()
		mask, _       = netip.AddrFromSlice(net.CIDRMask(prefix.Bits(), ip.BitLen()))
	)

	fd, err := socketCloexec(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Close(fd)
	}()

	var name [unix.IFNAMSIZ]byte
	copy(name[:], interfaceName)
	ifra := ifreqAddr{
		Name: name,
		Addr: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   ip.As4(),
		},
	}

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

	var routeSocket int
	if routeSubscribe != nil {
		routeSocket = routeSubscribe.routeSocket
	} else {
		routeSocket, err = socketCloexec(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
		if err != nil {
			return fmt.Errorf("unable to create AF_ROUTE socket: %w", err)
		}
		defer func() {
			_ = unix.Shutdown(routeSocket, unix.SHUT_RDWR)
			_ = unix.Close(routeSocket)
		}()
	}

	var (
		routeAddr = &route.Inet4Addr{}
		maskAddr  = &route.Inet4Addr{}
		linkAddr  = &route.Inet4Addr{
			IP: ip.As4(),
		}
	)

	routeAddr.IP = gw.As4()
	maskAddr.IP = mask.As4()
	_ = addRoute(routeSocket, routeAddr, maskAddr, linkAddr, unix.RTF_HOST)

	if autoRoute {
		routes := append(defaultRoutes, prefix.String())
		for _, r := range routes {
			_, cidr, _ := net.ParseCIDR(r)

			copy(routeAddr.IP[:], cidr.IP.To4())
			copy(maskAddr.IP[:], cidr.Mask)

			err = addRoute(routeSocket, routeAddr, maskAddr, linkAddr, 0)
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
	if routeCancel != nil {
		monitorMux.Unlock()
		return
	}

	routeCtx, routeCancel = context.WithCancel(context.Background())
	monitorMux.Unlock()

	var (
		err       error
		routeChan = make(chan *net.Interface)
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

	tunStatus = C.TunEnabled

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
	rib, err := route.FetchRIB(unix.AF_UNSPEC, unix.NET_RT_DUMP2, 0)
	if err != nil {
		return nil, fmt.Errorf("route.FetchRIB: %w", err)
	}

	msgs, err := route.ParseRIB(unix.NET_RT_IFLIST2, rib)
	if err != nil {
		return nil, fmt.Errorf("route.ParseRIB: %w", err)
	}

	for _, message := range msgs {
		routeMessage := message.(*route.RouteMessage)
		if (routeMessage.Flags & unix.RTF_GATEWAY) == 0 {
			continue
		}

		addresses := routeMessage.Addrs

		var via netip.Addr
		switch ra := addresses[0].(type) {
		case *route.Inet4Addr:
			via = netip.AddrFrom4(ra.IP)
		case *route.Inet6Addr:
			via = netip.AddrFrom16(ra.IP)
		}

		if !via.IsValid() || !via.IsUnspecified() || len(addresses) < 2 {
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

		ip, _ := netip.AddrFromSlice(addrs[0].(*net.IPNet).IP)

		var gw netip.Addr
		switch ra := addresses[1].(type) {
		case *route.Inet4Addr:
			gw = netip.AddrFrom4(ra.IP)
		case *route.Inet6Addr:
			gw = netip.AddrFrom16(ra.IP)
		}

		return &DefaultInterface{
			Name:    ifaceM.Name,
			Index:   routeMessage.Index,
			IP:      ip.Unmap(),
			Gateway: gw,
		}, nil
	}

	return nil, errInterfaceNotFound
}

func defaultRouteChangeCallback(update *net.Interface) {
	routeChangeMux.Lock()
	defer routeChangeMux.Unlock()

	if strings.HasPrefix(update.Name, "utun") {
		return
	}

	onChangeDefaultRoute()
}

func addRoute(sock int, addr, mask *route.Inet4Addr, link *route.Inet4Addr, flag int) error {
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

//go:linkname ioctlPtr golang.org/x/sys/unix.ioctlPtr
func ioctlPtr(_ int, _ uint, _ unsafe.Pointer) (err error)

type ifreqAddr struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
}

type subscriber struct {
	ch   chan<- *net.Interface
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

			log.Error().
				Err(err).
				Int("routeSocket", s.routeSocket).
				Msg("[TUN] failed to read route message, unsubscribed route event notifications")
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

		if msg == nil || msg.Index == 0 {
			continue
		}

		ifaceM, err := retryInterfaceByIndex(msg.Index)
		if err != nil {
			continue
		}

		s.ch <- ifaceM
	}
}
