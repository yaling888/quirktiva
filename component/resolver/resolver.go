package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/samber/lo"

	"github.com/Dreamacro/clash/component/trie"
)

var (
	// DefaultResolver aim to resolve ip
	DefaultResolver Resolver

	// ProxyServerHostResolver resolve ip to proxies server host
	ProxyServerHostResolver Resolver

	// DisableIPv6 means don't resolve ipv6 host
	// default value is true
	DisableIPv6 = true

	// DefaultHosts aim to resolve hosts
	DefaultHosts = trie.New[netip.Addr]()

	// DefaultDNSTimeout defined the default dns request timeout
	DefaultDNSTimeout = time.Second * 5
)

var (
	ErrIPNotFound   = errors.New("couldn't find ip")
	ErrIPVersion    = errors.New("ip version error")
	ErrIPv6Disabled = errors.New("ipv6 disabled")
)

const proxyServerIPKey = ipContextKey("key-lookup-proxy-server-ip")

const (
	typeNone uint16 = 0
	typeA    uint16 = 1
	typeAAAA uint16 = 28
)

type ipContextKey string

type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]netip.Addr, error)
	LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error)
	LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error)
	ResolveIP(host string) (ip netip.Addr, err error)
	ResolveIPv4(host string) (ip netip.Addr, err error)
	ResolveIPv6(host string) (ip netip.Addr, err error)
	ExchangeContext(ctx context.Context, m *dns.Msg) (msg *dns.Msg, err error)
}

// LookupIP with a host, return ip list
func LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPByResolver(ctx, host, DefaultResolver)
}

// LookupIPv4 with a host, return ipv4 list
func LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupIPByResolverAndType(ctx, host, DefaultResolver, typeA)
}

// LookupIPv6 with a host, return ipv6 list
func LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupIPByResolverAndType(ctx, host, DefaultResolver, typeAAAA)
}

// LookupIPByResolver same as ResolveIP, but with a resolver
func LookupIPByResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	return lookupIPByResolverAndType(ctx, host, r, typeNone)
}

// LookupFirstIP with a host, return first ip
func LookupFirstIP(ctx context.Context, host string) (netip.Addr, error) {
	ips, err := LookupIP(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[0], nil
}

// ResolveIP with a host, return ip
func ResolveIP(host string) (netip.Addr, error) {
	return resolveIPByType(host, typeNone)
}

// ResolveIPv4 with a host, return ipv4
func ResolveIPv4(host string) (netip.Addr, error) {
	return resolveIPByType(host, typeA)
}

// ResolveIPv6 with a host, return ipv6
func ResolveIPv6(host string) (netip.Addr, error) {
	return resolveIPByType(host, typeAAAA)
}

// ResolveProxyServerHost proxies server host only
func ResolveProxyServerHost(host string) (netip.Addr, error) {
	return resolveProxyServerHostByType(host, typeNone)
}

// ResolveIPv4ProxyServerHost proxies server host only
func ResolveIPv4ProxyServerHost(host string) (netip.Addr, error) {
	return resolveProxyServerHostByType(host, typeA)
}

// ResolveIPv6ProxyServerHost proxies server host only
func ResolveIPv6ProxyServerHost(host string) (netip.Addr, error) {
	return resolveProxyServerHostByType(host, typeAAAA)
}

func IsProxyServerIP(ctx context.Context) bool {
	return ctx.Value(proxyServerIPKey) != nil
}

func resolveIPByType(host string, _type uint16) (netip.Addr, error) {
	var (
		ips []netip.Addr
		err error
	)

	switch _type {
	case typeNone:
		ips, err = LookupIP(context.Background(), host)
	case typeA:
		ips, err = LookupIPv4(context.Background(), host)
	default:
		ips, err = LookupIPv6(context.Background(), host)
	}

	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}

	return ips[rand.Intn(len(ips))], nil
}

func resolveProxyServerHostByType(host string, _type uint16) (netip.Addr, error) {
	var (
		ips []netip.Addr
		err error
		ctx = context.WithValue(context.Background(), proxyServerIPKey, struct{}{})
	)

	if ProxyServerHostResolver != nil {
		ips, err = lookupIPByResolverAndType(ctx, host, ProxyServerHostResolver, _type)
	} else {
		ips, err = lookupIPByResolverAndType(ctx, host, DefaultResolver, _type)
	}

	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}

	return ips[rand.Intn(len(ips))], nil
}

func lookupIPByResolverAndType(ctx context.Context, host string, r Resolver, t uint16) ([]netip.Addr, error) {
	if t == typeAAAA && DisableIPv6 {
		return nil, ErrIPv6Disabled
	}

	if node := DefaultHosts.Search(host); node != nil {
		ip := node.Data
		if t != typeAAAA {
			ip = ip.Unmap()
		}
		if t == typeNone || (t == typeA && ip.Is4()) || (t == typeAAAA && ip.Is6()) {
			return []netip.Addr{ip}, nil
		}
	}

	if r != nil {
		if t == typeA {
			return r.LookupIPv4(ctx, host)
		} else if t == typeAAAA {
			return r.LookupIPv6(ctx, host)
		}
		if DisableIPv6 {
			return r.LookupIPv4(ctx, host)
		}
		return r.LookupIP(ctx, host)
	} else if t == typeNone && DisableIPv6 {
		return LookupIPv4(ctx, host)
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		if t != typeAAAA {
			ip = ip.Unmap()
		}
		is4 := ip.Is4()
		if (t == typeA && !is4) || (t == typeAAAA && is4) {
			return nil, ErrIPVersion
		}
		return []netip.Addr{ip}, nil
	}

	network := "ip"
	if t == typeA {
		network = "ip4"
	} else if t == typeAAAA {
		network = "ip6"
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	} else if len(ips) == 0 {
		return nil, ErrIPNotFound
	}

	return lo.Map(ips, func(item net.IP, _ int) netip.Addr {
		ip, _ := netip.AddrFromSlice(item)
		if t != typeAAAA {
			ip = ip.Unmap()
		}
		return ip
	}), nil
}
