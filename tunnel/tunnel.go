package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/phuslu/log"
	"github.com/samber/lo"
	"github.com/samber/lo/mutable"
	"go.uber.org/atomic"
	"golang.org/x/net/http/httpguts"

	"github.com/yaling888/quirktiva/adapter/inbound"
	N "github.com/yaling888/quirktiva/common/net"
	"github.com/yaling888/quirktiva/common/pipe"
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
	natTable     = nat.New[string, *udpNatConn]()
	sniTable     = nat.New[string, *sniPacketWriter]()
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

	// mitm
	mitmMux          sync.Mutex
	mitmConnIn       chan<- C.ConnContext
	mitmGetTLSConfig func(host string) *tls.Config

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

// SetMitmOptions set the MITM options
func SetMitmOptions(in chan<- C.ConnContext, tlsCfg func(host string) *tls.Config) {
	mitmMux.Lock()
	mitmConnIn = in
	mitmGetTLSConfig = tlsCfg
	mitmMux.Unlock()
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
			hasV6  = rawProxy.HasV6()
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
	rAddrs, err := resolver.LookupIP(context.Background(), metadata.Host)
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
	needSniffing := needSniffingSNI(metadata)
	if !needSniffing && metadata.DstPort != 443 {
		return sniffer.OFF, nil
	}

	sniffingType := sniffer.OFF
	if needSniffing {
		sniffingType = sniffer.TLS
	}

	const sniffTLSTimeout = 50 * time.Millisecond

	readOnlyConn := sniffer.StreamReadOnlyConn(connCtx.Conn())

	hostname, attemptECH := sniffer.SniffTLS(readOnlyConn, sniffTLSTimeout)
	if hostname == "" && needSniffing {
		sniffingType = sniffer.HTTP
		readOnlyConn = sniffer.StreamReadOnlyConn(readOnlyConn)
		hostname = sniffer.SniffHTTP(readOnlyConn, time.Millisecond)
	}

	connCtx.InjectConn(readOnlyConn.UnreadConn())

	metadata.SNI = hostname
	metadata.IsECH = attemptECH

	if hostname == metadata.Host {
		// Client attempts ECH, doesn't mean that ECH is accepted by the remote server.
		// May use dns resolver to look up the ECH configs.
		if attemptECH {
			metadata.IsECH = false
		}
		return sniffer.OFF, nil
	}
	if !needSniffing || attemptECH {
		return sniffer.OFF, nil
	}

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

func sniffUDP(conn net.PacketConn, metadata *C.Metadata) (sniffer.SniffingType, error) {
	const sniffQUICTimeout = 200 * time.Millisecond

	hostname, attemptECH := sniffer.SniffQUIC(conn, sniffQUICTimeout)

	metadata.SNI = hostname
	metadata.IsECH = attemptECH

	if hostname == metadata.Host {
		if attemptECH {
			metadata.IsECH = false
		}
		return sniffer.OFF, nil
	}
	if !needSniffingSNI(metadata) || attemptECH {
		return sniffer.OFF, nil
	}

	if sniffer.VerifyHostnameInSNI(hostname) {
		metadata.Host = sniffer.ToLowerASCII(hostname)
		if resolver.MappingEnabled() {
			metadata.DNSMode = C.DNSSniffing
			if resolver.FakeIPEnabled() {
				metadata.DstIP = netip.Addr{}
			}
		}
		return sniffer.QUIC, nil
	} else if resolver.IsFakeIP(metadata.DstIP) {
		return sniffer.OFF, fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
	}
	return sniffer.OFF, nil
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
		fAddr   netip.Addr // make a fAddr if request ip is fakeip
		key     = packet.LocalAddr().String() + metadata.RemoteAddress()
		lockKey = key + "-lock"
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

	handlePacketLock := func(w *sniPacketWriter, ch chan struct{}) {
		if ch != nil {
			close(ch)
		}
		w.hl.Lock()
		w.hl.Wait()
		if w.er == nil {
			handleUDPConnNatTable(packet, fAddr, key, lockKey)
		} else {
			packet.Drop()
		}
		w.hl.Unlock()
	}

	if natTable.Exist(key) || natTable.Exist(lockKey) || (!needSniffingSNI(metadata) && metadata.DstPort != 443) {
		w, loaded := sniTable.Load(key)
		if !loaded {
			handleUDPConnNatTable(packet, fAddr, key, lockKey)
			return
		}
		go handlePacketLock(w, nil)
		return
	}

	sw, loaded := sniTable.LoadOrStore(key, &sniPacketWriter{
		wl: nat.NewLocker(nil),
		hl: nat.NewLocker(func() { sniTable.Delete(key) }),
	})

	go func() {
		if loaded {
			sw.wl.Lock()
			locked := make(chan struct{})
			go handlePacketLock(sw, locked)
			<-locked
			sw.wl.Wait()
			_, _ = sw.w.Write(*packet.Data())
			sw.wl.Unlock()
			return
		}

		defer func() {
			sw.hl.TryRelease()
			sw.hl.Done()
		}()

		r, w := pipe.Pipe()
		sw.w = w

		go func() {
			_, _ = w.Write(*packet.Data())
			sw.wl.Done()
		}()

		logHost := metadata.Host
		logDstIP := metadata.DstIP
		sType, err := sniffUDP(sniffer.NewReadOnlyPacketConn(r), metadata)
		_ = r.Close()

		if err != nil {
			sw.er = err
			packet.Drop()

			log.Debug().Err(err).Msg("[Sniffer] sniff failed")
			return
		}
		if sType != sniffer.OFF {
			log.Debug().
				Str("host", logHost).
				Str("newHost", metadata.Host).
				NetIPAddr("ip", logDstIP).
				Str("port", metadata.DstPort.String()).
				Msg("[Sniffer] update quic sni")
		}
		handleUDPConnNatTable(packet, fAddr, key, lockKey)
	}()
}

func handleUDPConnNatTable(packet *inbound.PacketAdapter, fAddr netip.Addr, key, lockKey string) {
	metadata := packet.Metadata()

	if pc, ok := natTable.Load(key); ok {
		metadata.DstIP = pc.a
		lock, loaded := natTable.GetLock(lockKey)
		if !loaded {
			_ = handleUDPToRemote(packet, pc.c, metadata)
			packet.Drop()
			return
		}
		go func() {
			lock.Lock()
			lock.Wait()
			_ = handleUDPToRemote(packet, pc.c, metadata)
			lock.Unlock()
			packet.Drop()
		}()
		return
	}

	lock, loaded := natTable.GetOrCreateLock(lockKey, func() { natTable.Delete(lockKey) })

	go func() {
		defer packet.Drop()

		if loaded {
			lock.Lock()
			lock.Wait()
			if pc, ok := natTable.Load(key); ok {
				metadata.DstIP = pc.a
				_ = handleUDPToRemote(packet, pc.c, metadata)
			}
			lock.Unlock()
			return
		}

		defer func() {
			lock.TryRelease()
			lock.Done()
		}()

		if e := log.Debug(); e != nil {
			e.EmbedObject(metadata).Any("inbound", metadata.Type).Msg("[UDP] accept session")
		}

		if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
			metadata.DstIP = node.Data
			metadata.DNSMode = C.DNSNormal
		}

		pCtx := icontext.NewPacketConnContext(metadata)

		var (
			proxy C.Proxy
			rule  C.Rule
		)
		if !shouldHandleMITM(metadata, C.Direct) {
			p, r, err := resolveMetadata(pCtx, metadata)
			if err != nil {
				log.Warn().Err(err).Msg("[Metadata] parse failed")
				return
			}
			proxy = p
			rule = r
		} else {
			proxy = proxies["REJECT"]
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
			mutable.Reverse(chains)
			rawPc.SetChains(chains)
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

		natTable.Set(key, &udpNatConn{c: pc, a: oAddr})
		_ = handleUDPToRemote(packet, pc, metadata)
	}()
}

func handleTCPConn(connCtx C.ConnContext) {
	defer func() {
		if !connCtx.Hijacked() {
			_ = connCtx.Conn().Close()
		}
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

	logDstIP := metadata.DstIP
	sType, err := sniffTCP(connCtx, metadata)
	if err != nil {
		log.Debug().Err(err).Msg("[Sniffer] sniff failed")
		return
	}
	if sType != sniffer.OFF {
		if e := log.Debug(); e != nil {
			e.
				Str("host", metadata.Host).
				NetIPAddr("ip", logDstIP).
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

	rawProxy, chains := FetchRawProxyAdapter(proxy, metadata)

	var connState *tls.ConnectionState
	if shouldHandleMITM(metadata, rawProxy.Type()) {
		var ok bool
		connState, ok, err = handleTCPMITM(connCtx)
		if err != nil {
			log.Warn().Err(err).Msg("[TCP] failed to process mitm")
			return
		}
		if ok {
			connCtx.Hijack()

			log.Debug().
				EmbedObject(metadata).
				Str("proxy", rawProxy.Name()).
				Msg("[TCP] hijack mitm connection")
			return
		}
	}

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
		mutable.Reverse(chains)
		remoteConn.SetChains(chains)
	}

	if rawProxy.Type() != C.Reject {
		remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule)
	}

	defer func(remoteConn C.Conn) {
		_ = remoteConn.Close()
	}(remoteConn)

	switch {
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

	if connState == nil {
		handleSocket(connCtx, remoteConn)
		return
	}

	outConn, err := streamServerTLSConn(connState, remoteConn)
	if err != nil {
		log.Warn().
			Err(err).
			EmbedObject(metadata).
			Any("proxy", remoteConn).
			Msg("[TCP] failed to tls handshake server for missing mitm")
		return
	}
	defer outConn.Close()

	log.Info().
		EmbedObject(metadata).
		Any("mode", mode).
		Any("proxy", remoteConn).
		Msg("[TCP] stream server tls connection for missing mitm")
	handleSocket(connCtx, outConn)
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

func shouldHandleMITM(metadata *C.Metadata, adpType C.AdapterType) bool {
	if mitmConnIn == nil || metadata.Type == C.MITM || adpType == C.Reject {
		return false
	}
	if metadata.Type == C.MITM_ALL {
		metadata.Type = C.MITM
		return true
	}
	if metadata.DstPort == 80 || (rewriteHosts != nil && rewriteHosts.Search(metadata.String()) != nil) {
		return true
	}
	return false
}

func streamServerTLSConn(state *tls.ConnectionState, conn C.Conn) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	cfg := &tls.Config{
		ServerName: state.ServerName,
		NextProtos: []string{state.NegotiatedProtocol},
		MinVersion: state.Version,
	}
	serverTLSConn := tls.Client(conn, cfg)
	if err := serverTLSConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return serverTLSConn, nil
}

func handleTCPMITM(connCtx C.ConnContext) (state *tls.ConnectionState, ok bool, err error) {
	c := connCtx.Conn()
	rw := N.NewBufferedConn(c)
	connCtx.InjectConn(rw)

	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	b, err := rw.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		if os.IsTimeout(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	// client TLS handshake.
	if b[0] == 0x16 {
		mitmMux.Lock()
		if mitmGetTLSConfig == nil {
			mitmMux.Unlock()
			return nil, false, errors.New("mitm server is closed")
		}
		tlsConfig := mitmGetTLSConfig(connCtx.Metadata().String())
		mitmMux.Unlock()

		tlsConfig.NextProtos = []string{"h2", "unencrypted_http2", "http/1.1", "http/1.0"}
		clientTLSConn := tls.Server(rw, tlsConfig)

		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()
		if err = clientTLSConn.HandshakeContext(ctx); err != nil {
			return nil, false, err
		}

		connCtx.InjectConn(clientTLSConn)

		stas := clientTLSConn.ConnectionState()
		switch strings.ToLower(stas.NegotiatedProtocol) {
		case "h2", "unencrypted_http2", "http/1.1", "http/1.0", "dns":
		default:
			return &stas, false, nil
		}
	} else {
		if rw.Buffered() < 7 {
			return nil, false, nil
		}
		buf, _ := rw.Peek(7)
		if !isHTTPTraffic(buf) {
			return nil, false, nil
		}
	}

	mitmMux.Lock()
	defer mitmMux.Unlock()
	if mitmConnIn != nil {
		connCtx.Metadata().Type = C.MITM
		mitmConnIn <- connCtx
		return nil, true, nil
	}
	return nil, false, nil
}

func isHTTPTraffic(buf []byte) bool {
	method, _, _ := strings.Cut(string(buf), " ")
	return validMethod(method)
}

func validMethod(method string) bool {
	return len(method) > 0 && strings.IndexFunc(method, func(r rune) bool {
		return !httpguts.IsTokenRune(r)
	}) == -1
}

type udpNatConn struct {
	c C.PacketConn
	a netip.Addr
}

type sniPacketWriter struct {
	w  *pipe.PipeWriter
	wl *nat.Lock // writer lock
	hl *nat.Lock // handler lock
	er error
}
