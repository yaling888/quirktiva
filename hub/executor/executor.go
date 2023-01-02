package executor

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/phuslu/log"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outboundgroup"
	"github.com/Dreamacro/clash/component/auth"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/component/profile"
	"github.com/Dreamacro/clash/component/profile/cachefile"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/component/trie"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/listener"
	authStore "github.com/Dreamacro/clash/listener/auth"
	L "github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"
)

var mux sync.Mutex

func readConfig(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file %s is empty", path)
	}

	return data, err
}

// Parse config with default config path
func Parse() (*config.Config, error) {
	return ParseWithPath(C.Path.Config())
}

// ParseWithPath parse config with custom config path
func ParseWithPath(path string) (*config.Config, error) {
	buf, err := readConfig(path)
	if err != nil {
		return nil, err
	}

	return ParseWithBytes(buf)
}

// ParseWithBytes config with buffer
func ParseWithBytes(buf []byte) (*config.Config, error) {
	return config.Parse(buf)
}

// ApplyConfig dispatch configure to all parts
func ApplyConfig(cfg *config.Config, force bool) {
	mux.Lock()
	defer mux.Unlock()

	if cfg.General.LogLevel == L.DEBUG {
		L.SetLevel(L.DEBUG)
	} else {
		L.SetLevel(L.INFO)
	}

	updateUsers(cfg.Users)
	updateProxies(cfg.Proxies, cfg.Providers)
	updateRules(cfg.Rules)
	updateScript(cfg.RuleProviders, cfg.MainMatcher)
	updateHosts(cfg.Hosts)
	updateMitm(cfg.Mitm)
	updateProfile(cfg)
	updateDNS(cfg.DNS, &cfg.General.Tun)
	updateGeneral(cfg.General, force)
	updateExperimental(cfg)
	updateTunnels(cfg.Tunnels)

	L.SetLevel(cfg.General.LogLevel)
}

func GetGeneral() *config.General {
	ports := listener.GetPorts()
	authenticator := []string{}
	if authM := authStore.Authenticator(); authM != nil {
		authenticator = authM.Users()
	}

	general := &config.General{
		Inbound: config.Inbound{
			Port:           ports.Port,
			SocksPort:      ports.SocksPort,
			RedirPort:      ports.RedirPort,
			TProxyPort:     ports.TProxyPort,
			MixedPort:      ports.MixedPort,
			MitmPort:       ports.MitmPort,
			Authentication: authenticator,
			AllowLan:       listener.AllowLan(),
			BindAddress:    listener.BindAddress(),
		},
		Mode:     tunnel.Mode(),
		LogLevel: L.Level(),
		IPv6:     !resolver.DisableIPv6,
		Sniffing: tunnel.Sniffing(),
		Tun:      listener.GetTunConf(),
	}

	return general
}

func updateExperimental(c *config.Config) {
	tunnel.UDPFallbackMatch.Store(c.Experimental.UDPFallbackMatch)

	udpPolicy := c.Experimental.UDPFallbackPolicy
	if strings.EqualFold(udpPolicy, "direct") || strings.EqualFold(udpPolicy, "reject") {
		udpPolicy = strings.ToUpper(udpPolicy)
	}
	tunnel.UDPFallbackPolicy.Store(udpPolicy)
}

func updateDNS(c *config.DNS, t *config.Tun) {
	cfg := dns.Config{
		Main:         c.NameServer,
		Fallback:     c.Fallback,
		IPv6:         c.IPv6,
		EnhancedMode: c.EnhancedMode,
		Pool:         c.FakeIPRange,
		Hosts:        c.Hosts,
		FallbackFilter: dns.FallbackFilter{
			GeoIP:     c.FallbackFilter.GeoIP,
			GeoIPCode: c.FallbackFilter.GeoIPCode,
			IPCIDR:    c.FallbackFilter.IPCIDR,
			Domain:    c.FallbackFilter.Domain,
			GeoSite:   c.FallbackFilter.GeoSite,
		},
		Default:     c.DefaultNameserver,
		Policy:      c.NameServerPolicy,
		ProxyServer: c.ProxyServerNameserver,
	}

	// deprecated warning
	if cfg.EnhancedMode == C.DNSMapping {
		log.Warn().Msgf("[DNS] %s is deprecated, please use %s instead", cfg.EnhancedMode.String(), C.DNSFakeIP.String())
	}

	r := dns.NewResolver(cfg)
	pr := dns.NewProxyServerHostResolver(r)
	m := dns.NewEnhancer(cfg)

	// reuse cache of old host mapper
	if old := resolver.DefaultHostMapper; old != nil {
		m.PatchFrom(old.(*dns.ResolverEnhancer))
	}

	resolver.DefaultResolver = r
	resolver.DefaultHostMapper = m

	if pr.HasProxyServer() {
		resolver.ProxyServerHostResolver = pr
	}

	if t.Enable {
		resolver.DefaultLocalServer = dns.NewLocalServer(r, m)
	}

	if c.Enable {
		dns.ReCreateServer(c.Listen, r, m)
	} else {
		if !t.Enable {
			resolver.DefaultResolver = nil
			resolver.DefaultHostMapper = nil
			resolver.DefaultLocalServer = nil
			resolver.ProxyServerHostResolver = nil
		}
		dns.ReCreateServer("", nil, nil)
	}

	if cfg.Pool != nil {
		t.TunAddressPrefix = cfg.Pool.IPNet()
	}
}

func updateHosts(tree *trie.DomainTrie[netip.Addr]) {
	resolver.DefaultHosts = tree
}

func updateProxies(proxies map[string]C.Proxy, providers map[string]provider.ProxyProvider) {
	tunnel.UpdateProxies(proxies, providers)
}

func updateRules(rules []C.Rule) {
	tunnel.UpdateRules(rules)
}

func updateScript(providers map[string]C.Rule, matcher C.Matcher) {
	tunnel.UpdateScript(providers, matcher)
}

func updateMitm(mitm *config.Mitm) {
	tunnel.UpdateRewrites(mitm.Hosts, mitm.Rules)
}

func updateTunnels(tunnels []config.Tunnel) {
	listener.PatchTunnel(tunnels, tunnel.TCPIn(), tunnel.UDPIn())
}

func updateGeneral(general *config.General, force bool) {
	tunnel.SetMode(general.Mode)
	resolver.DisableIPv6 = !general.IPv6

	dialer.DefaultInterface.Store(general.Interface)
	if dialer.DefaultInterface.Load() != "" {
		log.Info().Str("name", general.Interface).Msg("[Config] interface")
	}

	if general.RoutingMark > 0 || (general.RoutingMark == 0 && general.TProxyPort == 0) {
		dialer.DefaultRoutingMark.Store(int32(general.RoutingMark))
		if general.RoutingMark > 0 {
			log.Info().Int("mark", general.RoutingMark).Msg("[Config] routing")
		}
	}

	iface.FlushCache()

	if !force {
		return
	}

	allowLan := general.AllowLan
	listener.SetAllowLan(allowLan)

	bindAddress := general.BindAddress
	listener.SetBindAddress(bindAddress)

	sniffing := general.Sniffing
	tunnel.SetSniffing(sniffing)

	log.Info().Bool("sniffing", sniffing).Msg("[Config] tls")

	tcpIn := tunnel.TCPIn()
	udpIn := tunnel.UDPIn()

	listener.ReCreateHTTP(general.Port, tcpIn)
	listener.ReCreateSocks(general.SocksPort, tcpIn, udpIn)
	listener.ReCreateRedir(general.RedirPort, tcpIn, udpIn)
	listener.ReCreateAutoRedir(general.EBpf.AutoRedir, tcpIn, udpIn)
	listener.ReCreateTProxy(general.TProxyPort, tcpIn, udpIn)
	listener.ReCreateMixed(general.MixedPort, tcpIn, udpIn)
	listener.ReCreateMitm(general.MitmPort, tcpIn)
	listener.ReCreateTun(&general.Tun, tcpIn, udpIn)
	listener.ReCreateRedirToTun(general.EBpf.RedirectToTun)
}

func updateUsers(users []auth.AuthUser) {
	authenticator := auth.NewAuthenticator(users)
	authStore.SetAuthenticator(authenticator)
	if authenticator != nil {
		log.Info().Msg("[Inbound] authentication of local server updated")
	}
}

func updateProfile(cfg *config.Config) {
	profileCfg := cfg.Profile

	profile.StoreSelected.Store(profileCfg.StoreSelected)
	if profileCfg.StoreSelected {
		patchSelectGroup(cfg.Proxies)
	}

	L.SetTracing(profileCfg.Tracing)
}

func patchSelectGroup(proxies map[string]C.Proxy) {
	mapping := cachefile.Cache().SelectedMap()
	if mapping == nil {
		return
	}

	for name, proxy := range proxies {
		outbound, ok := proxy.(*adapter.Proxy)
		if !ok {
			continue
		}

		selector, ok := outbound.ProxyAdapter.(*outboundgroup.Selector)
		if !ok {
			continue
		}

		selected, exist := mapping[name]
		if !exist {
			continue
		}

		_ = selector.Set(selected)
	}
}

func Shutdown() {
	listener.Cleanup()
	resolver.StoreFakePoolState()

	log.Warn().Msg("Clash shutting down")
}
