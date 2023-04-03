package resolver

import (
	"context"
	"errors"
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

	// DisableIPv6 means don't resolve ipv6 host
	// default value is true
	DisableIPv6 = true

	// RemoteDnsResolve reports whether TCP/UDP handler should be remote resolve DNS
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
	proxyServerHostKey = ipContextKey("key-lookup-proxy-server-ip")
	proxyKey           = ipContextKey("key-lookup-by-proxy")
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

// LookupIPByProxy with a host and proxy, reports force combined ipv6 list whether the DisableIPv6 value is true
func LookupIPByProxy(ctx context.Context, host, proxy string) ([]netip.Addr, error) {
	return lookupIPByProxyAndType(ctx, host, proxy, typeNone, true)
}

// LookupIPv4ByProxy with a host and proxy, reports ipv4 list
func LookupIPv4ByProxy(ctx context.Context, host, proxy string) ([]netip.Addr, error) {
	return lookupIPByProxyAndType(ctx, host, proxy, typeA, false)
}

// LookupIPv6ByProxy with a host and proxy, reports ipv6 list whether the DisableIPv6 value is true
func LookupIPv6ByProxy(ctx context.Context, host, proxy string) ([]netip.Addr, error) {
	return lookupIPByProxyAndType(ctx, host, proxy, typeAAAA, true)
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

// RemoveCache remove cache by host
func RemoveCache(host string) {
	if DefaultResolver != nil {
		DefaultResolver.RemoveCache(host)
	}
}

// IsProxyServer reports whether the DefaultResolver should be exchanged by proxyServer DNS client
func IsProxyServer(ctx context.Context) bool {
	return ctx.Value(proxyServerHostKey) != nil
}

// IsRemote reports whether the DefaultResolver should be exchanged by remote DNS client
func IsRemote(ctx context.Context) bool {
	return ctx.Value(proxyKey) != nil
}

// GetProxy reports the proxy name used by the DNS client and whether there is a proxy
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
	}

	return ips[rand.Intn(len(ips))], nil
}

func resolveProxyServerHostByType(host string, _type uint16) (netip.Addr, error) {
	var (
		ips []netip.Addr
		err error
		ctx = context.WithValue(context.Background(), proxyServerHostKey, struct{}{})
	)

	ips, err = lookupIPByResolverAndType(ctx, host, DefaultResolver, _type, true)
	if err != nil {
		return netip.Addr{}, err
	}

	return ips[rand.Intn(len(ips))], nil
}

func lookupIPByProxyAndType(ctx context.Context, host, proxy string, t uint16, both bool) ([]netip.Addr, error) {
	ctx = context.WithValue(ctx, proxyKey, proxy)
	return lookupIPByResolverAndType(ctx, host, DefaultResolver, t, both)
}

func lookupIPByResolverAndType(ctx context.Context, host string, r Resolver, t uint16, both bool) ([]netip.Addr, error) {
	if t == typeAAAA && DisableIPv6 && !both {
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
		if DisableIPv6 && !both {
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
