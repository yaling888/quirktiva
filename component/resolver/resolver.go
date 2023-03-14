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

	// RemoteResolver remote resolve DNS by a proxy
	RemoteResolver Resolver

	// DisableIPv6 means don't resolve ipv6 host
	// default value is true
	DisableIPv6 = true

	// RemoteDnsResolve reports remote resolve DNS
	// default value is true
	RemoteDnsResolve = true

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

const (
	proxyServerIPKey = ipContextKey("key-lookup-proxy-server-ip")
	proxyKey         = ipContextKey("key-lookup-by-proxy")
)

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
	RemoveCache(host string)
}

// LookupIP with a host, return ip list
func LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPByResolver(ctx, host, DefaultResolver)
}

// LookupIPv4 with a host, return ipv4 list
func LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupIPByResolverAndType(ctx, host, DefaultResolver, typeA, false)
}

// LookupIPv6 with a host, return ipv6 list
func LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return lookupIPByResolverAndType(ctx, host, DefaultResolver, typeAAAA, false)
}

// LookupIPByResolver same as ResolveIP, but with a resolver
func LookupIPByResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	return lookupIPByResolverAndType(ctx, host, r, typeNone, false)
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

// ResolveIPByProxy with a host and proxy, return ip
func ResolveIPByProxy(host, proxy string, first bool) (netip.Addr, error) {
	ctx := context.WithValue(context.Background(), proxyKey, proxy)
	ips, err := LookupIPByResolver(ctx, host, RemoteResolver)
	l := len(ips)
	if err != nil {
		return netip.Addr{}, err
	} else if l == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	if first || l == 1 {
		return ips[0], nil
	}
	return ips[rand.Intn(l)], nil
}

func RemoveCache(host string) {
	if ProxyServerHostResolver != nil {
		ProxyServerHostResolver.RemoveCache(host)
	}
	if DefaultResolver != nil {
		DefaultResolver.RemoveCache(host)
	}
}

func IsProxyServerIP(ctx context.Context) bool {
	return ctx.Value(proxyServerIPKey) != nil
}

func GetProxy(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(proxyKey).(string)
	return v, ok
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
		ips, err = lookupIPByResolverAndType(ctx, host, ProxyServerHostResolver, _type, true)
	} else {
		ips, err = lookupIPByResolverAndType(ctx, host, DefaultResolver, _type, true)
	}

	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}

	return ips[rand.Intn(len(ips))], nil
}

func lookupIPByResolverAndType(ctx context.Context, host string, r Resolver, t uint16, isProxyHost bool) ([]netip.Addr, error) {
	if t == typeAAAA && DisableIPv6 && !isProxyHost {
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
		if DisableIPv6 && !isProxyHost {
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
