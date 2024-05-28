package dns

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"sync"
	"time"

	D "github.com/miekg/dns"
	"github.com/phuslu/log"
	"github.com/samber/lo"
	"go.uber.org/atomic"
	"golang.org/x/sync/singleflight"

	"github.com/yaling888/quirktiva/common/cache"
	"github.com/yaling888/quirktiva/component/fakeip"
	"github.com/yaling888/quirktiva/component/geodata/router"
	"github.com/yaling888/quirktiva/component/resolver"
	"github.com/yaling888/quirktiva/component/trie"
	C "github.com/yaling888/quirktiva/constant"
)

type dnsClient interface {
	Exchange(m *D.Msg) (msg *rMsg, err error)
	ExchangeContext(ctx context.Context, m *D.Msg) (msg *rMsg, err error)
	IsLan() bool
}

type result struct {
	Msg    *rMsg
	Error  error
	Policy bool
}

type rMsg struct {
	Msg    *D.Msg
	Source string
	Lan    bool
}

func (m *rMsg) Copy() *rMsg {
	m1 := new(rMsg)
	m1.Msg = m.Msg.Copy()
	m1.Source = m.Source
	m1.Lan = m.Lan
	return m1
}

var _ resolver.Resolver = (*Resolver)(nil)

type Resolver struct {
	ipv6                  bool
	hosts                 *trie.DomainTrie[netip.Addr]
	main                  []dnsClient
	fallback              []dnsClient
	proxyServer           []dnsClient
	remote                []dnsClient
	fallbackDomainFilters []fallbackDomainFilter
	fallbackIPFilters     []fallbackIPFilter
	group                 singleflight.Group
	lruCache              *cache.LruCache[string, *rMsg]
	policy                *trie.DomainTrie[*Policy]
	searchDomains         []string
}

// LookupIP request with TypeA and TypeAAAA, priority return TypeA
func (r *Resolver) LookupIP(ctx context.Context, host string) (ip []netip.Addr, err error) {
	ctx1, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip6, err6 := r.lookupIP(ctx1, host, D.TypeAAAA)
		if err6 != nil {
			return
		}
		ch <- ip6
	}()

	ip, err = r.lookupIP(ctx1, host, D.TypeA)
	if err == nil {
		if resolver.IsRemote(ctx) { // force combine ipv6 list for remote resolve DNS
			if ip6, open := <-ch; open {
				ip = append(ip, ip6...)
			}
		}
		return
	}

	ip, open := <-ch
	if !open {
		return nil, resolver.ErrIPNotFound
	}

	return ip, nil
}

// ResolveIP request with TypeA and TypeAAAA, priority return TypeA
func (r *Resolver) ResolveIP(host string) (ip netip.Addr, err error) {
	ips, err := r.LookupIP(context.Background(), host)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, host)
	}
	return ips[rand.IntN(len(ips))], nil
}

// LookupIPv4 request with TypeA
func (r *Resolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeA)
}

// ResolveIPv4 request with TypeA
func (r *Resolver) ResolveIPv4(host string) (ip netip.Addr, err error) {
	ips, err := r.lookupIP(context.Background(), host, D.TypeA)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, host)
	}
	return ips[rand.IntN(len(ips))], nil
}

// LookupIPv6 request with TypeAAAA
func (r *Resolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeAAAA)
}

// ResolveIPv6 request with TypeAAAA
func (r *Resolver) ResolveIPv6(host string) (ip netip.Addr, err error) {
	ips, err := r.lookupIP(context.Background(), host, D.TypeAAAA)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, host)
	}
	return ips[rand.IntN(len(ips))], nil
}

func (r *Resolver) shouldIPFallback(ip netip.Addr) bool {
	for _, filter := range r.fallbackIPFilters {
		if filter.Match(ip) {
			return true
		}
	}
	return false
}

// Exchange a batch of dns request, and it uses cache
func (r *Resolver) Exchange(m *D.Msg) (msg *D.Msg, source string, err error) {
	return r.ExchangeContext(context.Background(), m)
}

// ExchangeContext a batch of dns request with context.Context, and it uses cache
func (r *Resolver) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, source string, err error) {
	if len(m.Question) == 0 {
		return nil, "", errors.New("should have one question at least")
	}

	var (
		q   = m.Question[0]
		key = genMsgCacheKey(ctx, q)
	)

	cacheM, expireTime, hit := r.lruCache.GetWithExpire(key)
	if hit && time.Now().Before(expireTime) {
		msg1 := cacheM.Copy()
		msg = msg1.Msg
		source = msg1.Source
		setMsgMaxTTL(msg, uint32(time.Until(expireTime).Seconds()))
		return
	}
	msg1, err := r.exchangeWithoutCache(ctx, m, q, key, true)
	if err != nil {
		return nil, "", err
	}
	return msg1.Msg, msg1.Source, nil
}

// ExchangeContextWithoutCache a batch of dns request with context.Context
func (r *Resolver) ExchangeContextWithoutCache(ctx context.Context, m *D.Msg) (msg *D.Msg, source string, err error) {
	if len(m.Question) == 0 {
		return nil, "", errors.New("should have one question at least")
	}

	var (
		q   = m.Question[0]
		key = genMsgCacheKey(ctx, q)
	)

	msg1, err := r.exchangeWithoutCache(ctx, m, q, key, false)
	if err != nil {
		return nil, "", err
	}
	return msg1.Msg, msg1.Source, nil
}

// exchangeWithoutCache a batch of dns request, and it does NOT GET from cache
func (r *Resolver) exchangeWithoutCache(ctx context.Context, m *D.Msg, q D.Question, key string, cache bool) (msg *rMsg, err error) {
	domain := strings.TrimSuffix(q.Name, ".")
	ret, err, shared := r.group.Do(key, func() (res any, err error) {
		defer func() {
			if err != nil || !cache {
				return
			}

			msg1 := res.(*rMsg)

			// OPT RRs MUST NOT be cached, forwarded, or stored in or loaded from master files.
			msg1.Msg.Extra = lo.Filter(msg1.Msg.Extra, func(rr D.RR, index int) bool {
				return rr.Header().Rrtype != D.TypeOPT
			})

			// skip dns cache for acme challenge
			if q.Qtype == D.TypeTXT && strings.HasPrefix(q.Name, "_acme-challenge.") {
				log.Debug().
					Str("source", msg1.Source).
					Str("qType", D.Type(q.Qtype).String()).
					Str("name", q.Name).
					Msg("[DNS] dns cache ignored because of acme challenge")
				return
			}

			if resolver.IsProxyServer(ctx) {
				// reset proxy server ip cache expire time to at least 20 minutes
				sec := max(minTTL(msg1.Msg.Answer), 1200)
				putMsgToCacheWithExpire(r.lruCache, key, msg1, sec)
				return
			}

			if msg1.Msg.Rcode == D.RcodeNameError { // Non-Existent Domain
				setTTL(msg1.Msg.Ns, 600, true)
			}

			putMsgToCache(r.lruCache, key, msg1)
		}()

		isIPReq := isIPRequest(q)
		if isIPReq {
			return r.ipExchange(ctx, m, domain)
		}

		var rst *result
		if r.remote != nil && resolver.IsRemote(ctx) {
			rst = r.exchangePolicyCombine(ctx, r.remote, m, domain)
		} else if r.proxyServer != nil && resolver.IsProxyServer(ctx) {
			rst = r.exchangePolicyCombine(ctx, r.proxyServer, m, domain)
		} else {
			rst = r.exchangePolicyCombine(ctx, r.main, m, domain)
		}
		return rst.Msg, rst.Error
	})

	if err == nil {
		msg = ret.(*rMsg)
		if shared {
			msg = msg.Copy()
		}
	}

	return
}

func (r *Resolver) matchPolicy(domain string) ([]dnsClient, bool) {
	if r.policy == nil || domain == "" {
		return nil, false
	}

	record := r.policy.Search(domain)
	if record == nil {
		return nil, false
	}

	return record.Data.GetData(), true
}

func (r *Resolver) exchangePolicyCombine(ctx context.Context, clients []dnsClient, m *D.Msg, domain string) *result {
	timeout := resolver.DefaultDNSTimeout
	if resolver.IsRemote(ctx) {
		timeout = proxyTimeout
	}

	res := new(result)
	policyClients, match := r.matchPolicy(domain)
	if !match {
		ctx1, cancel := context.WithTimeout(resolver.CopyCtxValues(ctx), timeout)
		defer cancel()
		res.Msg, res.Error = batchExchange(ctx1, clients, m)
		return res
	}

	isLan := lo.SomeBy(policyClients, func(c dnsClient) bool {
		return c.IsLan()
	})

	if !isLan {
		ctx1, cancel := context.WithTimeout(resolver.CopyCtxValues(ctx), timeout)
		defer cancel()
		res.Msg, res.Error = batchExchange(ctx1, policyClients, m)
		res.Policy = true
		return res
	}

	var (
		res1, res2 *result
		done1      = atomic.NewBool(false)
		wg         = sync.WaitGroup{}
	)

	wg.Add(2)

	ctx1, cancel1 := context.WithTimeout(resolver.CopyCtxValues(ctx), resolver.DefaultDNSTimeout)
	defer cancel1()

	ctx2, cancel2 := context.WithTimeout(resolver.CopyCtxValues(ctx), timeout)
	defer cancel2()

	go func() {
		msg, err := batchExchange(ctx1, policyClients, m)
		res1 = &result{Msg: msg, Error: err, Policy: true}
		done1.Store(true)
		wg.Done()
		if err == nil {
			cancel2() // no need to wait for others
		}
	}()

	go func() {
		msg, err := batchExchange(ctx2, clients, m)
		res2 = &result{Msg: msg, Error: err}
		wg.Done()
		if err == nil && !done1.Load() {
			// if others done before lan policy, then wait maximum 50ms for lan policy
			for i := 0; i < 10; i++ {
				time.Sleep(5 * time.Millisecond)
				if done1.Load() { // check for every 5ms
					return
				}
			}
			cancel1()
		}
	}()

	wg.Wait()

	if res1.Error == nil {
		res = res1
	} else {
		res = res2
	}

	if res.Error == nil {
		res.Msg.Lan = true
		setMsgMaxTTL(res.Msg.Msg, 10) // reset ttl to maximum 10 seconds for lan policy
	}
	return res
}

func (r *Resolver) shouldOnlyQueryFallback(domain string) bool {
	if r.fallback == nil || r.fallbackDomainFilters == nil || domain == "" {
		return false
	}

	for _, df := range r.fallbackDomainFilters {
		if df.Match(domain) {
			return true
		}
	}

	return false
}

func (r *Resolver) ipExchange(ctx context.Context, m *D.Msg, domain string) (msg *rMsg, err error) {
	if r.remote != nil && resolver.IsRemote(ctx) {
		res := r.exchangePolicyCombine(ctx, r.remote, m, domain)
		return res.Msg, res.Error
	}

	if r.proxyServer != nil && resolver.IsProxyServer(ctx) {
		res := r.exchangePolicyCombine(ctx, r.proxyServer, m, domain)
		return res.Msg, res.Error
	}

	if r.shouldOnlyQueryFallback(domain) {
		res := r.exchangePolicyCombine(ctx, r.fallback, m, domain)
		return res.Msg, res.Error
	}

	res := r.exchangePolicyCombine(ctx, r.main, m, domain)
	msg, err = res.Msg, res.Error

	if res.Policy { // directly return if from policy servers
		return
	}

	if r.fallback == nil { // directly return if no fallback servers are available
		return
	}

	if err == nil {
		if ips := msgToIP(msg.Msg); len(ips) != 0 {
			if lo.EveryBy(ips, func(ip netip.Addr) bool {
				return !r.shouldIPFallback(ip)
			}) {
				// no need to wait for fallback result
				return
			}
		}
	}

	res = r.exchangePolicyCombine(ctx, r.fallback, m, domain)
	msg, err = res.Msg, res.Error
	return
}

func (r *Resolver) lookupIP(ctx context.Context, host string, dnsType uint16) ([]netip.Addr, error) {
	ip, err := netip.ParseAddr(host)
	if err == nil {
		if dnsType != D.TypeAAAA {
			ip = ip.Unmap()
		}
		isIPv4 := ip.Is4()
		if dnsType == D.TypeAAAA && !isIPv4 {
			return []netip.Addr{ip}, nil
		} else if dnsType == D.TypeA && isIPv4 {
			return []netip.Addr{ip}, nil
		} else {
			return nil, resolver.ErrIPVersion
		}
	}

	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), dnsType)

	msg, _, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return nil, err
	}

	ips := msgToIP(msg)
	if len(ips) != 0 {
		return ips, nil
	} else if len(r.searchDomains) == 0 {
		return nil, resolver.ErrIPNotFound
	}

	for _, domain := range r.searchDomains {
		q := &D.Msg{}
		q.SetQuestion(D.Fqdn(fmt.Sprintf("%s.%s", host, domain)), dnsType)
		msg1, _, err1 := r.ExchangeContext(ctx, q)
		if err1 != nil {
			return nil, err1
		}
		ips1 := msgToIP(msg1)
		if len(ips1) != 0 {
			return ips1, nil
		}
	}

	return nil, resolver.ErrIPNotFound
}

func (r *Resolver) RemoveCache(host string) {
	q := D.Question{Name: D.Fqdn(host), Qtype: D.TypeA, Qclass: D.ClassINET}
	r.lruCache.Delete(genMsgCacheKey(context.Background(), q))
	q.Qtype = D.TypeAAAA
	r.lruCache.Delete(genMsgCacheKey(context.Background(), q))
}

type NameServer struct {
	Net       string
	Addr      string
	Interface string
	Proxy     string
	IsDHCP    bool
}

type FallbackFilter struct {
	GeoIP     bool
	GeoIPCode string
	IPCIDR    []*netip.Prefix
	Domain    []string
	GeoSite   []*router.DomainMatcher
}

type Config struct {
	Main, Fallback []NameServer
	Default        []NameServer
	ProxyServer    []NameServer
	Remote         []NameServer
	IPv6           bool
	EnhancedMode   C.DNSMode
	FallbackFilter FallbackFilter
	Pool           *fakeip.Pool
	Hosts          *trie.DomainTrie[netip.Addr]
	Policy         map[string]NameServer
	SearchDomains  []string
}

func NewResolver(config Config) *Resolver {
	defaultResolver := &Resolver{
		main: transform(config.Default, nil),
		lruCache: cache.New[string, *rMsg](
			cache.WithSize[string, *rMsg](128),
			cache.WithStale[string, *rMsg](true),
		),
	}

	r := &Resolver{
		ipv6: config.IPv6,
		main: transform(config.Main, defaultResolver),
		lruCache: cache.New[string, *rMsg](
			cache.WithSize[string, *rMsg](10240),
			cache.WithStale[string, *rMsg](true),
		),
		hosts:         config.Hosts,
		searchDomains: config.SearchDomains,
	}

	if len(config.Fallback) != 0 {
		r.fallback = transform(config.Fallback, defaultResolver)
	}

	if len(config.ProxyServer) != 0 {
		r.proxyServer = transform(config.ProxyServer, defaultResolver)
	}

	if len(config.Remote) != 0 {
		remotes := lo.Map(config.Remote, func(item NameServer, _ int) NameServer {
			item.Proxy = "remote-resolver"
			return item
		})
		r.remote = transform(remotes, defaultResolver)
	}

	if len(config.Policy) != 0 {
		r.policy = trie.New[*Policy]()
		for domain, nameserver := range config.Policy {
			_ = r.policy.Insert(domain, NewPolicy(transform([]NameServer{nameserver}, defaultResolver)))
		}
	}

	var fallbackIPFilters []fallbackIPFilter
	if config.FallbackFilter.GeoIP {
		fallbackIPFilters = append(fallbackIPFilters, &geoipFilter{
			code: config.FallbackFilter.GeoIPCode,
		})
	}
	for _, ipnet := range config.FallbackFilter.IPCIDR {
		fallbackIPFilters = append(fallbackIPFilters, &ipnetFilter{ipnet: ipnet})
	}
	r.fallbackIPFilters = fallbackIPFilters

	var fallbackDomainFilters []fallbackDomainFilter
	if len(config.FallbackFilter.Domain) != 0 {
		fallbackDomainFilters = append(fallbackDomainFilters, NewDomainFilter(config.FallbackFilter.Domain))
	}

	if len(config.FallbackFilter.GeoSite) != 0 {
		fallbackDomainFilters = append(fallbackDomainFilters, &geoSiteFilter{
			matchers: config.FallbackFilter.GeoSite,
		})
	}
	r.fallbackDomainFilters = fallbackDomainFilters

	return r
}
