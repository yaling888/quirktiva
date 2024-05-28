package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/phuslu/log"
	"github.com/samber/lo"
	"go.uber.org/atomic"

	A "github.com/yaling888/quirktiva/adapter"
	"github.com/yaling888/quirktiva/adapter/inbound"
	"github.com/yaling888/quirktiva/common/sniffer"
	"github.com/yaling888/quirktiva/component/nat"
	P "github.com/yaling888/quirktiva/component/process"
	"github.com/yaling888/quirktiva/component/resolver"
	"github.com/yaling888/quirktiva/component/trie"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/constant/provider"
	icontext "github.com/yaling888/quirktiva/context"
	"github.com/yaling888/quirktiva/tunnel/statistic"
)

var (
	tcpQueue     = make(chan C.ConnContext, 512)
	udpQueue     = make(chan *inbound.PacketAdapter, 1024)
	natTable     = nat.New[string, C.PacketConn]()
	addrTable    = nat.New[string, netip.Addr]()
	rules        []C.Rule
	proxies      = make(map[string]C.Proxy)
	providers    map[string]provider.ProxyProvider
	rewrites     C.RewriteRule
	rewriteHosts *trie.DomainTrie[bool]
	configMux    sync.RWMutex

	// Outbound Rule
	mode = Rule

	// sniffing switch
	sniffing = false

	// default timeout for UDP session
	udpTimeout = 60 * time.Second

	// mitmProxy mitm proxy
	mitmProxy C.Proxy

	// scriptMainMatcher script main function eval
	scriptMainMatcher C.Matcher

	scriptProxyProvidersGetter = func() map[string][]C.Proxy {
		providersMap := make(map[string][]C.Proxy)
		for k, v := range providers {
			providersMap[k] = v.Proxies()
		}
		return providersMap
	}

	UDPFallbackMatch  = atomic.NewBool(false)
	UDPFallbackPolicy = atomic.NewString("")
)

func init() {
	go process()
}

// TCPIn return fan-in queue
func TCPIn() chan<- C.ConnContext {
	return tcpQueue
}

// UDPIn return fan-in udp queue
func UDPIn() chan<- *inbound.PacketAdapter {
	return udpQueue
}

// Rules return all rules
func Rules() []C.Rule {
	return rules
}

// UpdateRules handle update rules
func UpdateRules(newRules []C.Rule) {
	configMux.Lock()
	rules = newRules
	configMux.Unlock()
}

// Proxies return all proxies
func Proxies() map[string]C.Proxy {
	return proxies
}

// Providers return all compatible providers
func Providers() map[string]provider.ProxyProvider {
	return providers
}

func FindProxyByName(name string) (proxy C.Proxy, found bool) {
	proxy, found = proxies[name]
	if found {
		return
	}
	pds := providers
	for _, pd := range pds {
		if pd.VehicleType() == provider.Compatible {
			continue
		}
		ps := pd.Proxies()
		for _, p := range ps {
			if found = p.Name() == name; found {
				proxy = p
				return
			}
		}
	}
	return
}

func FetchRawProxyAdapter(proxy C.Proxy, metadata *C.Metadata) (C.Proxy, []string) {
	var (
		chains   = []string{proxy.Name()}
		rawProxy = proxy
		subProxy = proxy.Unwrap(metadata)
	)
	for subProxy != nil {
		chains = append(chains, subProxy.Name())
		rawProxy = subProxy
		subProxy = subProxy.Unwrap(metadata)
	}
	return rawProxy, chains
}

// UpdateProxies handle update proxies
func UpdateProxies(newProxies map[string]C.Proxy, newProviders map[string]provider.ProxyProvider) {
	configMux.Lock()
	old := proxies
	oldPDs := providers
	proxies = newProxies
	providers = newProviders
	C.GetScriptProxyProviders = scriptProxyProvidersGetter
	statistic.DefaultManager.Cleanup()
	provider.Cleanup(old, oldPDs)
	configMux.Unlock()
}

// Mode return current mode
func Mode() TunnelMode {
	return mode
}

// SetMode change the mode of tunnel
func SetMode(m TunnelMode) {
	mode = m
}

func Sniffing() bool {
	return sniffing
}

func SetSniffing(s bool) {
	sniffing = s
}

// SetMitmOutbound set the MITM outbound
func SetMitmOutbound(outbound C.ProxyAdapter) {
	if outbound != nil {
		mitmProxy = A.NewProxy(outbound)
	} else {
		mitmProxy = nil
	}
}

// Rewrites return all rewrites
func Rewrites() C.RewriteRule {
	return rewrites
}

// UpdateRewrites handle update rewrites
func UpdateRewrites(hosts *trie.DomainTrie[bool], rules C.RewriteRule) {
	configMux.Lock()
	rewriteHosts = hosts
	rewrites = rules
	configMux.Unlock()
}

// UpdateScript update script config
func UpdateScript(providers map[string]C.Rule, matcher C.Matcher) {
	configMux.Lock()
	C.SetScriptRuleProviders(providers)
	scriptMainMatcher = matcher
	configMux.Unlock()
}

// processUDP starts a loop to handle udp packet
func processUDP() {
	queue := udpQueue
	for conn := range queue {
		handleUDPConn(conn)
	}
}

func process() {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}
	for i := 0; i < numUDPWorkers; i++ {
		go processUDP()
	}

	queue := tcpQueue
	for conn := range queue {
		go handleTCPConn(conn)
	}
}

func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP.IsValid()
}

func preHandleMetadata(metadata *C.Metadata) error {
	// handle IP string on host
	if ip, err := netip.ParseAddr(metadata.Host); err == nil {
		metadata.DstIP = ip
		metadata.Host = ""
	}

	// preprocess enhanced-mode metadata
	if needLookupIP(metadata) {
		host, exist := resolver.FindHostByIP(metadata.DstIP)
		if exist {
			metadata.Host = host
			if resolver.FakeIPEnabled() {
				metadata.DstIP = netip.Addr{}
				metadata.DNSMode = C.DNSFakeIP
			} else {
				metadata.DNSMode = C.DNSMapping
			}
		} else if resolver.IsFakeIP(metadata.DstIP) && !sniffing {
			return fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	}

	return nil
}

func resolveMetadata(_ C.PlainContext, metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	if metadata.NetWork == C.TCP && mitmProxy != nil && metadata.Type != C.MITM &&
		((rewriteHosts != nil && rewriteHosts.Search(metadata.String()) != nil) || metadata.DstPort == 80) {
		proxy = mitmProxy
		return
	}

	if metadata.SpecialProxy != "" {
		var exist bool
		proxy, exist = FindProxyByName(metadata.SpecialProxy)
		if !exist {
			err = fmt.Errorf("proxy %s not found", metadata.SpecialProxy)
		}
		return
	}

	switch mode {
	case Rule:
		proxy, rule, err = match(metadata)
	case Script:
		proxy, err = matchScript(metadata)
		if err != nil {
			err = fmt.Errorf("execute script failed: %w", err)
		}
	case Direct:
		proxy = proxies["DIRECT"]
	case Global:
		proxy = proxies["GLOBAL"]
	default:
		panic(fmt.Sprintf("unknown mode: %s", mode))
	}
	return
}

func resolveDNS(metadata *C.Metadata, proxy, rawProxy C.Proxy) (isRemote bool, err error) {
	if metadata.Host == "" ||
		metadata.DNSMode == C.DNSMapping ||
		(metadata.DNSMode == C.DNSNormal && metadata.DstIP.IsValid()) {
		return
	}

	if proxy.DisableDnsResolve() || rawProxy.DisableDnsResolve() {
		isRemote = false
	} else {
		isRemote = resolver.RemoteDnsResolve
	}

	isUDP := metadata.NetWork == C.UDP

	if isRemote {
		var (
			hasV6  = rawProxy.HasV6() && !(isUDP && metadata.Type == C.TUN)
			rAddrs []netip.Addr
		)
		if hasV6 {
			rAddrs, err = resolver.LookupIPByProxy(context.Background(), metadata.Host, rawProxy.Name())
		} else {
			rAddrs, err = resolver.LookupIPv4ByProxy(context.Background(), metadata.Host, rawProxy.Name())
		}
		if err != nil {
			if metadata.DNSMode == C.DNSSniffing && metadata.DstIP.IsValid() {
				err = nil
				isRemote = false
			}
			return
		}
		if isUDP {
			metadata.DstIP = rAddrs[0]
			return
		}
		if hasV6 {
			v6 := lo.Filter(rAddrs, func(addr netip.Addr, _ int) bool {
				return addr.Is6()
			})
			if len(v6) > 0 {
				rAddrs = v6 // priority use ipv6
			}
		}
		metadata.DstIP = rAddrs[rand.IntN(len(rAddrs))]
		return
	}
	if isUDP {
		err = localResolveDNS(metadata, false, true)
		return
	}
	if metadata.DNSMode == C.DNSSniffing {
		if er := localResolveDNS(metadata, true, true); er == nil && rawProxy.Type() != C.Direct {
			metadata.DstIP = netip.Addr{}
		}
	}
	return
}

func localResolveDNS(metadata *C.Metadata, force, udp bool) (err error) {
	if !force && metadata.Resolved() {
		return nil
	}
	var rAddrs []netip.Addr
	if udp && metadata.Type == C.TUN {
		rAddrs, err = resolver.LookupIPv4(context.Background(), metadata.Host)
	} else {
		rAddrs, err = resolver.LookupIP(context.Background(), metadata.Host)
	}
	if err != nil {
		return err
	}
	if udp {
		metadata.DstIP = rAddrs[0]
	} else {
		metadata.DstIP = rAddrs[rand.IntN(len(rAddrs))]
	}
	return nil
}

func needSniffingSNI(metadata *C.Metadata) bool {
	return sniffing && (metadata.Host == "" || metadata.DNSMode == C.DNSMapping)
}

func sniffTCP(connCtx C.ConnContext, metadata *C.Metadata) (sniffer.SniffingType, error) {
	if !needSniffingSNI(metadata) {
		return sniffer.OFF, nil
	}

	const sniffTLSTimeout = 50 * time.Millisecond

	sniffingType := sniffer.TLS
	readOnlyConn := sniffer.StreamReadOnlyConn(connCtx.Conn())

	hostname := sniffer.SniffTLS(readOnlyConn, sniffTLSTimeout)
	if hostname == "" {
		sniffingType = sniffer.HTTP
		readOnlyConn = sniffer.StreamReadOnlyConn(readOnlyConn)
		hostname = sniffer.SniffHTTP(readOnlyConn, time.Millisecond)
	}

	connCtx.InjectConn(readOnlyConn.UnreadConn())

	if sniffer.VerifyHostnameInSNI(hostname) {
		metadata.Host = sniffer.ToLowerASCII(hostname)
		if resolver.MappingEnabled() {
			metadata.DNSMode = C.DNSSniffing
			if resolver.FakeIPEnabled() {
				metadata.DstIP = netip.Addr{}
			}
		}
	} else {
		sniffingType = sniffer.OFF
		if resolver.IsFakeIP(metadata.DstIP) {
			return sniffer.OFF, fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	}
	return sniffingType, nil
}

func sniffUDP(buf []byte, metadata *C.Metadata) (sniffer.SniffingType, error) {
	if !needSniffingSNI(metadata) || len(buf) < 1200 {
		return sniffer.OFF, nil
	}

	const sniffQUICTimeout = 3 * time.Millisecond

	tried := false
	r := bytes.NewReader(buf)
retry:
	hostname := sniffer.SniffQUIC(sniffer.NewFakePacketConn(r), sniffQUICTimeout)
	if hostname == "" && !tried {
		tried = true
		r.Reset(buf)
		goto retry
	}

	sniffingType := sniffer.QUIC
	if sniffer.VerifyHostnameInSNI(hostname) {
		metadata.Host = sniffer.ToLowerASCII(hostname)
		if resolver.MappingEnabled() {
			metadata.DNSMode = C.DNSSniffing
			if resolver.FakeIPEnabled() {
				metadata.DstIP = netip.Addr{}
			}
		}
	} else {
		sniffingType = sniffer.OFF
		if resolver.IsFakeIP(metadata.DstIP) {
			return sniffer.OFF, fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	}
	return sniffingType, nil
}

func handleUDPConn(packet *inbound.PacketAdapter) {
	metadata := packet.Metadata()
	if !metadata.Valid() {
		log.Warn().Msgf("[Metadata] not valid: %#v", metadata)
		packet.Drop()
		return
	}

	if packet.Data() == nil {
		log.Warn().Str("rAddr", metadata.RemoteAddress()).Msg("[UDP] invalid udp payload")
		return
	}

	var (
		fAddr netip.Addr // make a fAddr if request ip is fakeip
		key   = packet.LocalAddr().String() + metadata.RemoteAddress()
	)

	if ip, err := netip.ParseAddr(metadata.Host); err == nil {
		metadata.DstIP = ip
		metadata.Host = ""
	}

	if resolver.IsExistFakeIP(metadata.DstIP) {
		fAddr = metadata.DstIP
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debug().Err(err).Msg("[Metadata] prehandle failed")
		packet.Drop()
		return
	}

	handle := func() bool {
		if pc, ok := natTable.Load(key); ok {
			if metadata.DstIP, ok = addrTable.Load(key); !ok {
				return false
			}
			_ = handleUDPToRemote(packet, pc, metadata)
			return true
		}
		return false
	}

	if handle() {
		packet.Drop()
		return
	}

	lockKey := key + "-lock"
	cond, loaded := natTable.GetOrCreateLock(lockKey)

	go func() {
		defer packet.Drop()

		if loaded {
			cond.L.Lock()
			cond.Wait()
			handle()
			cond.L.Unlock()
			return
		}

		defer func() {
			natTable.Delete(lockKey)
			cond.Broadcast()
		}()

		sType, err := sniffUDP(*packet.Data(), metadata)
		if err != nil {
			log.Debug().Err(err).Msg("[Sniffer] sniff failed")
			return
		}
		if sType != sniffer.OFF {
			if e := log.Debug(); e != nil {
				e.
					Str("host", metadata.Host).
					NetIPAddr("ip", metadata.DstIP).
					Str("port", metadata.DstPort.String()).
					Msg("[Sniffer] update quic sni")
			}
		}

		if e := log.Debug(); e != nil {
			e.EmbedObject(metadata).Any("inbound", metadata.Type).Msg("[UDP] accept session")
		}

		if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
			metadata.DstIP = node.Data
			metadata.DNSMode = C.DNSNormal
		}

		pCtx := icontext.NewPacketConnContext(metadata)
		proxy, rule, err := resolveMetadata(pCtx, metadata)
		if err != nil {
			log.Warn().Err(err).Msg("[Metadata] parse failed")
			return
		}

		rawProxy, chains := FetchRawProxyAdapter(proxy, metadata)

		isRemote, err := resolveDNS(metadata, proxy, rawProxy)
		if err != nil {
			if isRemote {
				log.Warn().Err(err).
					Str("proxy", rawProxy.Name()).
					Str("host", metadata.Host).
					Msg("[UDP] remote resolve DNS failed")
			} else {
				log.Warn().Err(err).
					Str("host", metadata.Host).
					Msg("[UDP] resolve DNS failed")
			}
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
		defer cancel()

		rawPc, err := rawProxy.ListenPacketContext(ctx, metadata)
		if err != nil {
			if rule == nil {
				log.Warn().
					Err(err).
					Str("proxy", rawProxy.Name()).
					Any("rAddr", C.LogAddr{M: *metadata}).
					Msg("[UDP] dial failed")
			} else {
				log.Warn().
					Err(err).
					Str("proxy", rawProxy.Name()).
					Any("rAddr", C.LogAddr{M: *metadata}).
					Any("rule", rule.RuleType()).
					Str("rulePayload", rule.Payload()).
					Any("ruleGroup", rule.RuleGroups()).
					Msg("[UDP] dial failed")
			}
			return
		}

		if len(chains) > 1 {
			rawPc.SetChains(lo.Reverse(chains))
		}

		pCtx.InjectPacketConn(rawPc)
		pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, rule)

		switch e := log.Info(); e != nil {
		case metadata.SpecialProxy != "":
			e.
				EmbedObject(metadata).
				Any("proxy", rawPc).
				Msg("[UDP] tunnel connected")
		case rule != nil:
			e.
				EmbedObject(metadata).
				Any("mode", mode).
				Any("rule", C.LogRule{R: rule}).
				Any("proxy", rawPc).
				Any("ruleGroup", rule.RuleGroups()).
				Msg("[UDP] connected")
		default:
			e.
				EmbedObject(metadata).
				Any("mode", mode).
				Any("proxy", rawPc).
				Msg("[UDP] connected")
		}

		oAddr := metadata.DstIP
		go handleUDPToLocal(packet.UDPPacket, pc, key, oAddr, fAddr)

		addrTable.Set(key, oAddr)
		natTable.Set(key, pc)
		handle()
	}()
}

func handleTCPConn(connCtx C.ConnContext) {
	defer func() {
		_ = connCtx.Conn().Close()
	}()

	metadata := connCtx.Metadata()
	if !metadata.Valid() {
		log.Warn().Msgf("[Metadata] not valid: %#v", metadata)
		return
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debug().Err(err).Msg("[Metadata] prehandle failed")
		return
	}

	sType, err := sniffTCP(connCtx, metadata)
	if err != nil {
		log.Debug().Err(err).Msg("[Sniffer] sniff failed")
		return
	}
	if sType != sniffer.OFF {
		if e := log.Debug(); e != nil {
			e.
				Str("host", metadata.Host).
				NetIPAddr("ip", metadata.DstIP).
				Str("port", metadata.DstPort.String()).
				Msgf("[Sniffer] update %s", sType.String())
		}
	}

	if e := log.Debug(); e != nil {
		e.EmbedObject(metadata).Any("inbound", metadata.Type).Msg("[TCP] accept connection")
	}

	if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
		metadata.DstIP = node.Data
		metadata.DNSMode = C.DNSNormal
	}

	proxy, rule, err := resolveMetadata(connCtx, metadata)
	if err != nil {
		log.Warn().Err(err).Msg("[Metadata] parse failed")
		return
	}

	var (
		rawProxy C.Proxy
		chains   []string

		isMitmOutbound = proxy == mitmProxy
	)

	if !isMitmOutbound {
		rawProxy, chains = FetchRawProxyAdapter(proxy, metadata)
		isRemote, err2 := resolveDNS(metadata, proxy, rawProxy)
		if err2 != nil {
			if isRemote {
				log.Warn().Err(err2).
					Str("proxy", rawProxy.Name()).
					Str("host", metadata.Host).
					Msg("[TCP] remote resolve DNS failed")
			} else {
				log.Warn().Err(err2).
					Str("host", metadata.Host).
					Msg("[TCP] resolve DNS failed")
			}
			return
		}
	} else {
		rawProxy = proxy
	}

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	remoteConn, err := rawProxy.DialContext(ctx, metadata)
	if err != nil {
		if rule == nil {
			log.Warn().
				Err(err).
				Str("proxy", rawProxy.Name()).
				Any("rAddr", C.LogAddr{M: *metadata}).
				Msg("[TCP] dial failed")
		} else {
			log.Warn().
				Err(err).
				Str("proxy", rawProxy.Name()).
				Any("rAddr", C.LogAddr{M: *metadata}).
				Any("rule", rule.RuleType()).
				Str("rulePayload", rule.Payload()).
				Any("ruleGroup", rule.RuleGroups()).
				Msg("[TCP] dial failed")
		}
		return
	}

	if len(chains) > 1 {
		remoteConn.SetChains(lo.Reverse(chains))
	}

	if rawProxy.Name() != "REJECT" && !isMitmOutbound {
		remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule)
	}

	defer func(remoteConn C.Conn) {
		_ = remoteConn.Close()
	}(remoteConn)

	switch {
	case isMitmOutbound:
	case metadata.SpecialProxy != "":
		if e := log.Info(); e != nil {
			e.
				EmbedObject(metadata).
				Any("proxy", remoteConn).
				Msg("[TCP] tunnel connected")
		}
	case rule != nil:
		if e := log.Info(); e != nil {
			e.
				EmbedObject(metadata).
				Any("mode", mode).
				Any("rule", C.LogRule{R: rule}).
				Any("proxy", remoteConn).
				Any("ruleGroup", rule.RuleGroups()).
				Msg("[TCP] connected")
		}
	default:
		if e := log.Info(); e != nil {
			e.
				EmbedObject(metadata).
				Any("mode", mode).
				Any("proxy", remoteConn).
				Msg("[TCP] connected")
		}
	}

	handleSocket(connCtx, remoteConn)
}

func shouldResolveIP(rule C.Rule, metadata *C.Metadata) bool {
	return rule.ShouldResolveIP() && metadata.Host != "" && !metadata.DstIP.IsValid()
}

func match(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	configMux.RLock()
	defer configMux.RUnlock()

	var (
		resolved     bool
		processFound bool
	)

	if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
		metadata.DstIP = node.Data
		resolved = true
	}

	adapter, rule := matchRule(rules, metadata, &resolved, &processFound)

	if adapter != nil {
		return adapter, rule, nil
	}

	if len(rules) == 0 {
		return proxies["DIRECT"], nil, nil
	}

	return proxies["REJECT"], nil, nil
}

func matchRule(subRules []C.Rule, metadata *C.Metadata, resolved, processFound *bool) (C.Proxy, C.Rule) {
	for _, rule := range subRules {
		if !*resolved && shouldResolveIP(rule, metadata) {
			rAddrs, err := resolver.LookupIP(context.Background(), metadata.Host)
			if err != nil {
				if e := log.Debug(); e != nil {
					e.
						Err(err).
						Str("host", metadata.Host).
						Msg("[Matcher] resolve failed")
				}
			} else {
				ip := rAddrs[0]
				if l := len(rAddrs); l > 1 && metadata.NetWork != C.UDP {
					ip = rAddrs[rand.IntN(l)]
				}
				if e := log.Debug(); e != nil {
					e.
						Str("host", metadata.Host).
						NetIPAddr("ip", ip).
						Msg("[Matcher] resolve success")
				}

				metadata.DstIP = ip
			}
			*resolved = true
		}

		if !*processFound && rule.ShouldFindProcess() {
			*processFound = true

			if metadata.OriginDst.IsValid() {
				path, err2 := P.FindProcessPath(
					metadata.NetWork.String(),
					netip.AddrPortFrom(metadata.SrcIP, uint16(metadata.SrcPort)),
					metadata.OriginDst,
				)

				if err2 != nil {
					if e := log.Debug(); e != nil {
						e.
							Err(err2).
							Any("addr", C.LogAddr{M: *metadata, HostOnly: true}).
							Msg("[Matcher] find process failed")
					}
				} else {
					if e := log.Debug(); e != nil {
						e.
							Any("addr", C.LogAddr{M: *metadata, HostOnly: true}).
							Str("path", path).
							Msg("[Matcher] find process success")
					}

					metadata.Process = filepath.Base(path)
					metadata.ProcessPath = path
				}
			}
		}

		if rule.Match(metadata) {
			if rule.RuleType() == C.Group {
				adapter, subRule := matchRule(rule.SubRules(), metadata, resolved, processFound)
				if adapter != nil {
					return adapter, subRule
				}
				continue
			}

			adapter, ok := FindProxyByName(rule.Adapter())
			if !ok {
				continue
			}

			extra := rule.RuleExtra()
			if extra != nil {
				if extra.NotMatchNetwork(metadata.NetWork) {
					continue
				}

				if extra.NotMatchSourceIP(metadata.SrcIP) {
					continue
				}

				if extra.NotMatchProcessName(metadata.Process) {
					continue
				}
			}

			if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
				if !UDPFallbackMatch.Load() {
					policy := UDPFallbackPolicy.Load()
					if policy != "" {
						if adapter2, ok2 := FindProxyByName(policy); ok2 {
							return adapter2, rule
						}
						log.Warn().
							Str("policy", policy).
							Msg("[Matcher] UDP fallback policy not found, skip use policy")
					}
				} else {
					log.Debug().
						Str("proxy", adapter.Name()).
						Msg("[Matcher] UDP is not supported, skip match")
					continue
				}
			}

			return adapter, rule
		}
	}

	return nil, nil
}

func matchScript(metadata *C.Metadata) (C.Proxy, error) {
	configMux.RLock()
	defer configMux.RUnlock()

	if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
		metadata.DstIP = node.Data
	}

	adapterName, err := scriptMainMatcher.Eval(metadata)
	if err != nil {
		return nil, err
	}

	adapter, ok := FindProxyByName(adapterName)
	if !ok {
		return nil, fmt.Errorf("proxy %s not found", adapterName)
	}

	if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
		if !UDPFallbackMatch.Load() {
			policy := UDPFallbackPolicy.Load()
			if policy != "" {
				if adapter2, ok2 := FindProxyByName(policy); ok2 {
					return adapter2, nil
				}
				log.Warn().
					Str("policy", policy).
					Msg("[Matcher] UDP fallback policy not found, skip use policy")
			}
		} else {
			log.Debug().
				Str("proxy", adapterName).
				Msg("[Matcher] UDP is not supported, use `REJECT` policy")
			return proxies["REJECT"], nil
		}
	}

	return adapter, nil
}
