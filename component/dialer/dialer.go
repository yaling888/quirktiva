package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/yaling888/quirktiva/component/resolver"
)

func DialContext(ctx context.Context, network, address string, options ...Option) (net.Conn, error) {
	opt := &option{
		interfaceName: DefaultInterface.Load(),
		routingMark:   int(DefaultRoutingMark.Load()),
	}

	for _, o := range DefaultOptions {
		if o == nil {
			continue
		}
		o(opt)
	}

	for _, o := range options {
		if o == nil {
			continue
		}
		o(opt)
	}

	switch network {
	case "tcp4", "tcp6", "udp4", "udp6":
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		portNum, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, &net.AddrError{Err: "invalid address for " + network, Addr: address}
		}

		var ip netip.Addr
		if a, err := netip.ParseAddr(host); err == nil {
			ip = a
		}

		switch network {
		case "tcp4", "udp4":
			if ip.IsValid() {
				if !ip.Is4() {
					return nil, &net.AddrError{Err: "invalid address for " + network, Addr: address}
				}
			} else {
				if !opt.direct {
					ip, err = resolver.ResolveIPv4ProxyServerHostWithContext(ctx, host)
				} else {
					ip, err = resolver.ResolveIPv4WithContext(ctx, host)
				}
			}
		default:
			if ip.IsValid() {
				if !ip.Is6() {
					return nil, &net.AddrError{Err: "invalid address for " + network, Addr: address}
				}
			} else {
				if !opt.direct {
					ip, err = resolver.ResolveIPv6ProxyServerHostWithContext(ctx, host)
				} else {
					ip, err = resolver.ResolveIPv6WithContext(ctx, host)
				}
			}
		}
		if err != nil {
			if _, ok := errors.AsType[net.Error](err); !ok {
				return nil, &net.DNSError{
					Name:       host,
					Err:        err.Error(),
					IsNotFound: errors.Is(err, resolver.ErrIPNotFound),
				}
			}
			return nil, err
		}

		return dialContext(ctx, network, netip.AddrPortFrom(ip, uint16(portNum)), opt)
	case "tcp", "udp":
		return dualStackDialContext(ctx, network, address, opt)
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

func DialContextAddrPort(ctx context.Context, network string, destination netip.AddrPort, options ...Option) (net.Conn, error) {
	opt := &option{
		interfaceName: DefaultInterface.Load(),
		routingMark:   int(DefaultRoutingMark.Load()),
	}

	for _, o := range DefaultOptions {
		if o == nil {
			continue
		}
		o(opt)
	}

	for _, o := range options {
		if o == nil {
			continue
		}
		o(opt)
	}

	return dialContext(ctx, network, destination, opt)
}

func ListenPacket(ctx context.Context, network, address string, options ...Option) (net.PacketConn, error) {
	cfg := &option{
		interfaceName: DefaultInterface.Load(),
		routingMark:   int(DefaultRoutingMark.Load()),
	}

	for _, o := range DefaultOptions {
		if o == nil {
			continue
		}
		o(cfg)
	}

	for _, o := range options {
		if o == nil {
			continue
		}
		o(cfg)
	}

	lc := &net.ListenConfig{}
	if cfg.interfaceName != "" {
		var (
			addr string
			err  error
		)
		if cfg.fallbackBind {
			addr, err = fallbackBindIfaceToListenConfig(cfg.interfaceName, lc, network, address)
		} else {
			addr, err = bindIfaceToListenConfig(cfg.interfaceName, lc, network, address)
		}
		if err != nil {
			return nil, err
		}
		address = addr
	}
	if cfg.addrReuse {
		addrReuseToListenConfig(lc)
	}
	if cfg.routingMark != 0 {
		bindMarkToListenConfig(cfg.routingMark, lc, network, address)
	}

	return lc.ListenPacket(ctx, network, address)
}

func dialContext(ctx context.Context, network string, destination netip.AddrPort, opt *option) (net.Conn, error) {
	dialer := &net.Dialer{}
	if opt.interfaceName != "" {
		if err := bindIfaceToDialer(opt.interfaceName, dialer, network, destination.Addr()); err != nil {
			return nil, err
		}
	}
	if opt.routingMark != 0 {
		bindMarkToDialer(opt.routingMark, dialer, network, destination.Addr())
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		return dialer.DialTCP(ctx, network, netip.AddrPort{}, destination)
	default:
		return dialer.DialUDP(ctx, network, netip.AddrPort{}, destination)
	}
}

func dualStackDialContext(ctx context.Context, network, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, &net.AddrError{Err: "invalid address for " + network, Addr: address}
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return dialContext(ctx, network, netip.AddrPortFrom(ip, uint16(portNum)), opt)
	}

	ctx1, cancel := context.WithCancel(ctx)
	returned := make(chan struct{})
	defer func() {
		cancel()
		close(returned)
	}()

	type dialResult struct {
		c        net.Conn
		err      error
		resolved bool
		ipv6     bool
		done     bool
	}
	results := make(chan dialResult)
	var primary, fallback dialResult

	startRacer := func(ctx context.Context, network, host string, direct bool, ipv6 bool) {
		result := dialResult{ipv6: ipv6, done: true, err: net.ErrClosed}
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.err == nil {
					_ = result.c.Close()
				}
			}
		}()

		var (
			ip  netip.Addr
			err error
		)
		if ipv6 {
			if !direct {
				ip, err = resolver.ResolveIPv6ProxyServerHostWithContext(ctx, host)
			} else {
				ip, err = resolver.ResolveIPv6WithContext(ctx, host)
			}
		} else {
			if !direct {
				ip, err = resolver.ResolveIPv4ProxyServerHostWithContext(ctx, host)
			} else {
				ip, err = resolver.ResolveIPv4WithContext(ctx, host)
			}
		}
		if err != nil {
			if _, ok := errors.AsType[net.Error](err); !ok {
				result.err = &net.DNSError{
					Name:       host,
					Err:        err.Error(),
					IsNotFound: errors.Is(err, resolver.ErrIPNotFound),
				}
				return
			}
			result.err = err
			return
		}
		result.resolved = true

		result.c, result.err = dialContext(ctx, network, netip.AddrPortFrom(ip, uint16(portNum)), opt)
	}

	go startRacer(ctx1, network+"4", host, opt.direct, false)
	go startRacer(ctx1, network+"6", host, opt.direct, true)

	for res := range results {
		if res.err == nil {
			return res.c, nil
		}

		if !res.ipv6 {
			primary = res
		} else {
			fallback = res
		}

		if primary.done && fallback.done {
			if primary.resolved {
				return nil, primary.err
			} else if fallback.resolved {
				return nil, fallback.err
			} else {
				return nil, fmt.Errorf("primary error: %w, fallback error: %w", primary.err, fallback.err)
			}
		}
	}

	panic("never touched")
}
