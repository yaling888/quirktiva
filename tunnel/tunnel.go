package tunnel

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/phuslu/log"
	"github.com/samber/lo"
	"go.uber.org/atomic"

	A "github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/component/nat"
	P "github.com/Dreamacro/clash/component/process"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	icontext "github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/tunnel/statistic"
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
		for _, p := range pd.Proxies() {
			found = p.Name() == name
			if found {
				proxy = p
				return
			}
		}
	}
	return
}

func FetchRawProxyAdapter(proxy C.Proxy, metadata *C.Metadata, chains []string) (C.Proxy, []string) {
	if chains != nil {
		chains = append(chains, proxy.Name())
	}
	if p := proxy.Unwrap(metadata); p != nil {
		return FetchRawProxyAdapter(p, metadata, chains)
	}
	return proxy, chains
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
			metadata.DNSMode = C.DNSMapping
			if resolver.FakeIPEnabled() {
				metadata.DstIP = netip.Addr{}
				metadata.DNSMode = C.DNSFakeIP
			} else if node := resolver.DefaultHosts.Search(host); node != nil {
				// redir-host should look up the hosts
				metadata.DstIP = node.Data
			}
		} else if resolver.IsFakeIP(metadata.DstIP) {
			return fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	}

	return nil
}

func resolveMetadata(_ C.PlainContext, metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	if metadata.NetWork == C.TCP && mitmProxy != nil && metadata.Type != C.MITM &&
		((rewriteHosts != nil && rewriteHosts.Search(metadata.String()) != nil) || metadata.DstPort == "80") {
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
	case Direct:
		proxy = proxies["DIRECT"]
	case Global:
		proxy = proxies["GLOBAL"]
	case Script:
		proxy, err = matchScript(metadata)
	// Rule
	default:
		proxy, rule, err = match(metadata)
	}
	return
}

func remoteResolveDNS(metadata *C.Metadata, proxy string, shouldRemoteResolve bool) (ok bool, err error) {
	if proxy == "REJECT" {
		return
	}
	if shouldRemoteResolve {
		if proxy == "DIRECT" {
			if !metadata.Resolved() {
				var rAddr netip.Addr
				rAddr, err = resolver.LookupFirstIP(context.Background(), metadata.Host)
				if err != nil {
					return
				}
				metadata.DstIP = rAddr
			}
		} else {
			ok = true
			var rAddr netip.Addr
			rAddr, err = resolver.ResolveIPByProxy(metadata.Host, proxy, true)
			if err != nil {
				return
			}
			metadata.DstIP = rAddr
		}
	} else if !metadata.Resolved() {
		var rAddr netip.Addr
		rAddr, err = resolver.LookupFirstIP(context.Background(), metadata.Host)
		if err != nil {
			return
		}
		metadata.DstIP = rAddr
	}
	return
}

func handleUDPConn(packet *inbound.PacketAdapter) {
	metadata := packet.Metadata()
	if !metadata.Valid() {
		log.Warn().Msgf("[Metadata] not valid: %#v", metadata)
		packet.Drop()
		return
	}

	var (
		fAddr netip.Addr // make a fAddr if request ip is fakeip
		rKey  string     // localAddrPort + remoteFakeIP + remotePort
		key   = packet.LocalAddr().String()
	)

	if resolver.IsExistFakeIP(metadata.DstIP) {
		fAddr = metadata.DstIP
		rKey = key + fAddr.String() + metadata.DstPort
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debug().Err(err).Msg("[Metadata] prehandle failed")
		packet.Drop()
		return
	}

	log.Debug().EmbedObject(metadata).Str("inbound", metadata.Type.String()).Msg("[UDP] accept session")

	handle := func() bool {
		pc := natTable.Get(key)
		if pc != nil {
			if !metadata.Resolved() {
				if rAddr := addrTable.Get(rKey); rAddr.IsValid() {
					metadata.DstIP = rAddr
				} else {
					return false
				}
			}
			_ = handleUDPToRemote(packet, pc, metadata)
			return true
		}
		return false
	}

	if handle() {
		return
	}

	lockKey := key + "-lock"
	cond, loaded := natTable.GetOrCreateLock(lockKey)

	go func() {
		if loaded {
			cond.L.Lock()
			cond.Wait()
			handle()
			cond.L.Unlock()
			return
		}

		var hdlErr error

		defer func() {
			natTable.Delete(lockKey)
			cond.Broadcast()
			if hdlErr != nil {
				packet.Drop()
			}
		}()

		pCtx := icontext.NewPacketConnContext(metadata)
		proxy, rule, hdlErr := resolveMetadata(pCtx, metadata)
		if hdlErr != nil {
			log.Warn().Err(hdlErr).Msg("[Metadata] parse failed")
			return
		}

		rawProxy, chains := FetchRawProxyAdapter(proxy, metadata, []string{})
		rawName := rawProxy.Name()

		isRemote, hdlErr := remoteResolveDNS(metadata, rawName, shouldRemoteResolveIP(rawProxy))
		if hdlErr != nil {
			if isRemote {
				log.Warn().Err(hdlErr).
					Str("proxy", rawName).
					Str("rAddr", metadata.RemoteAddress()).
					Msg("[UDP] remote resolve DNS failed")
			} else {
				log.Warn().Err(hdlErr).
					Str("rAddr", metadata.RemoteAddress()).
					Msg("[UDP] resolve DNS failed")
			}
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
		defer cancel()

		rawPc, hdlErr := rawProxy.ListenPacketContext(ctx, metadata.Pure(false))
		if hdlErr != nil {
			if rule == nil {
				log.Warn().
					Err(hdlErr).
					Str("proxy", rawName).
					Str("rAddr", metadata.RemoteAddress()).
					Msg("[UDP] dial failed")
			} else {
				log.Warn().
					Err(hdlErr).
					Str("proxy", rawName).
					Str("rAddr", metadata.RemoteAddress()).
					Str("rule", rule.RuleType().String()).
					Str("rulePayload", rule.Payload()).
					Msg("[UDP] dial failed")
			}
			return
		}

		if len(chains) > 1 {
			rawPc.SetChains(lo.Reverse(chains))
		}

		pCtx.InjectPacketConn(rawPc)
		pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, rule)

		entry := log.Info().EmbedObject(metadata)
		switch true {
		case metadata.SpecialProxy != "":
			entry = entry.
				Str("mode", "tunnel").
				Str("specialProxy", metadata.SpecialProxy).
				EmbedObject(rawPc)
		case rule != nil:
			entry = entry.
				EmbedObject(mode).
				Str("rule", fmt.Sprintf("%s(%s)", rule.RuleType().String(), rule.Payload())).
				EmbedObject(rawPc)
		default:
			entry = entry.EmbedObject(mode).EmbedObject(rawPc)
		}
		entry.Msg("[UDP] connected")

		oAddr := metadata.DstIP
		go handleUDPToLocal(packet.UDPPacket, pc, key, rKey, oAddr, fAddr)

		if rKey != "" {
			addrTable.Set(rKey, oAddr)
		}

		natTable.Set(key, pc)
		handle()
	}()
}

func handleTCPConn(connCtx C.ConnContext) {
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(connCtx.Conn())

	metadata := connCtx.Metadata()
	if !metadata.Valid() {
		log.Warn().Msgf("[Metadata] not valid: %#v", metadata)
		return
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debug().Err(err).Msg("[Metadata] prehandle failed")
		return
	}

	log.Debug().EmbedObject(metadata).Str("inbound", metadata.Type.String()).Msg("[TCP] accept connection")

	proxy, rule, err := resolveMetadata(connCtx, metadata)
	if err != nil {
		log.Warn().Err(err).Msg("[Metadata] parse failed")
		return
	}

	isMitmOutbound := proxy == mitmProxy

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	remoteConn, err := proxy.DialContext(ctx, metadata.Pure(isMitmOutbound))
	if err != nil {
		if rule == nil {
			log.Warn().
				Err(err).
				Str("proxy", proxy.Name()).
				Str("rAddr", metadata.RemoteAddress()).
				Msg("[TCP] dial failed")
		} else {
			log.Warn().
				Err(err).
				Str("proxy", proxy.Name()).
				Str("rAddr", metadata.RemoteAddress()).
				Str("rule", rule.RuleType().String()).
				Str("rulePayload", rule.Payload()).
				Msg("[TCP] dial failed")
		}
		return
	}

	if remoteConn.Chains().Last() != "REJECT" && !isMitmOutbound {
		remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule)
		if sniffing {
			remoteConn = statistic.NewSniffing(remoteConn, metadata, rule)
		}
	}

	defer func(remoteConn C.Conn) {
		_ = remoteConn.Close()
	}(remoteConn)

	switch true {
	case isMitmOutbound:
		break
	case metadata.SpecialProxy != "":
		log.Info().
			EmbedObject(metadata).
			Str("mode", "tunnel").
			Str("specialProxy", metadata.SpecialProxy).
			EmbedObject(remoteConn).
			Msg("[TCP] connected")
	case rule != nil:
		log.Info().
			EmbedObject(metadata).
			EmbedObject(mode).
			Str("rule", fmt.Sprintf("%s(%s)", rule.RuleType().String(), rule.Payload())).
			EmbedObject(remoteConn).
			Msg("[TCP] connected")
	default:
		log.Info().
			EmbedObject(metadata).
			EmbedObject(mode).
			EmbedObject(remoteConn).
			Msg("[TCP] connected")
	}

	handleSocket(connCtx, remoteConn)
}

func shouldResolveIP(rule C.Rule, metadata *C.Metadata) bool {
	return rule.ShouldResolveIP() && metadata.Host != "" && !metadata.DstIP.IsValid()
}

func shouldRemoteResolveIP(proxy C.Proxy) bool {
	if proxy.Type() == C.WireGuard {
		return proxy.(*A.Proxy).ProxyAdapter.(*outbound.WireGuard).RemoteDnsResolve()
	}
	return resolver.RemoteDnsResolve
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

	for _, rule := range rules {
		if !resolved && shouldResolveIP(rule, metadata) {
			rAddrs, err := resolver.LookupIP(context.Background(), metadata.Host)
			if err != nil {
				log.Debug().
					Err(err).
					Str("host", metadata.Host).
					Msg("[Matcher] resolve failed")
			} else {
				ip := rAddrs[0]
				if l := len(rAddrs); l > 1 && metadata.NetWork != C.UDP {
					ip = rAddrs[rand.Intn(l)]
				}
				log.Debug().
					Str("host", metadata.Host).
					Str("ip", ip.String()).
					Msg("[Matcher] resolve success")

				metadata.DstIP = ip
			}
			resolved = true
		}

		if !processFound && rule.ShouldFindProcess() {
			processFound = true

			srcPort, err := strconv.ParseUint(metadata.SrcPort, 10, 16)
			if err == nil {
				path, err := P.FindProcessName(metadata.NetWork.String(), metadata.SrcIP, int(srcPort))
				if err != nil {
					log.Debug().
						Err(err).
						Str("addr", metadata.String()).
						Msg("[Matcher] find process failed")
				} else {
					log.Debug().
						Str("addr", metadata.String()).
						Str("path", path).
						Msg("[Matcher] find process success")

					metadata.Process = filepath.Base(path)
					metadata.ProcessPath = path
				}
			}
		}

		if rule.Match(metadata) {
			adapter, ok := proxies[rule.Adapter()]
			if !ok {
				continue
			}

			if metadata.NetWork == C.UDP && !adapter.SupportUDP() && UDPFallbackMatch.Load() {
				log.Debug().
					Str("proxy", adapter.Name()).
					Msg("[Matcher] UDP is not supported, skip match")
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

			return adapter, rule, nil
		}
	}

	if adapter, ok := proxies[UDPFallbackPolicy.Load()]; ok {
		return adapter, nil, nil
	}

	return proxies["REJECT"], nil, nil
}

func matchScript(metadata *C.Metadata) (C.Proxy, error) {
	configMux.RLock()
	defer configMux.RUnlock()

	if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
		metadata.DstIP = node.Data
	}

	adapter, err := scriptMainMatcher.Eval(metadata)
	if err != nil {
		return nil, err
	}

	if proxy, ok := proxies[adapter]; !ok {
		return nil, fmt.Errorf("proxy adapter [%s] not found by script", adapter)
	} else if metadata.NetWork == C.UDP && !proxy.SupportUDP() {
		if UDPFallbackMatch.Load() {
			return nil, fmt.Errorf("proxy adapter [%s] UDP is not supported", adapter)
		} else if proxy, ok = proxies[UDPFallbackPolicy.Load()]; ok {
			return proxy, nil
		}
	}

	return proxies[adapter], nil
}
