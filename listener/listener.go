package listener

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phuslu/log"
	"github.com/samber/lo"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/common/cert"
	"github.com/Dreamacro/clash/component/ebpf"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/autoredir"
	"github.com/Dreamacro/clash/listener/http"
	"github.com/Dreamacro/clash/listener/mitm"
	"github.com/Dreamacro/clash/listener/mixed"
	"github.com/Dreamacro/clash/listener/redir"
	"github.com/Dreamacro/clash/listener/socks"
	"github.com/Dreamacro/clash/listener/tproxy"
	"github.com/Dreamacro/clash/listener/tun"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	"github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/listener/tunnel"
	rewrites "github.com/Dreamacro/clash/rewrite"
	T "github.com/Dreamacro/clash/tunnel"
)

var (
	allowLan    = false
	bindAddress = "*"
	lastTunConf *config.Tun

	socksListener      *socks.Listener
	socksUDPListener   *socks.UDPListener
	httpListener       *http.Listener
	redirListener      *redir.Listener
	redirUDPListener   *tproxy.UDPListener
	tproxyListener     *tproxy.Listener
	tproxyUDPListener  *tproxy.UDPListener
	mixedListener      *mixed.Listener
	mixedUDPLister     *socks.UDPListener
	tunStackListener   ipstack.Stack
	mitmListener       *mitm.Listener
	tcProgram          *ebpf.TcEBpfProgram
	autoRedirListener  *autoredir.Listener
	autoRedirProgram   *ebpf.TcEBpfProgram
	tunnelTCPListeners = map[string]*tunnel.Listener{}
	tunnelUDPListeners = map[string]*tunnel.PacketConn{}

	// lock for recreate function
	socksMux     sync.Mutex
	httpMux      sync.Mutex
	redirMux     sync.Mutex
	tproxyMux    sync.Mutex
	mixedMux     sync.Mutex
	tunMux       sync.Mutex
	mitmMux      sync.Mutex
	tcMux        sync.Mutex
	autoRedirMux sync.Mutex
	tunnelMux    sync.Mutex
)

type Ports struct {
	Port       int `json:"port"`
	SocksPort  int `json:"socks-port"`
	RedirPort  int `json:"redir-port"`
	TProxyPort int `json:"tproxy-port"`
	MixedPort  int `json:"mixed-port"`
	MitmPort   int `json:"mitm-port"`
}

func GetTunConf() config.Tun {
	if lastTunConf == nil {
		addrPort := C.DNSAddrPort{
			AddrPort: netip.MustParseAddrPort("0.0.0.0:53"),
		}
		return config.Tun{
			Enable: false,
			Stack:  C.TunGvisor,
			DNSHijack: []C.DNSUrl{ // default hijack all dns query
				{
					Network:  "udp",
					AddrPort: addrPort,
				},
				{
					Network:  "tcp",
					AddrPort: addrPort,
				},
			},
			AutoRoute:           true,
			AutoDetectInterface: false,
		}
	}
	return *lastTunConf
}

func AllowLan() bool {
	return allowLan
}

func BindAddress() string {
	return bindAddress
}

func SetAllowLan(al bool) {
	allowLan = al
}

func SetBindAddress(host string) {
	bindAddress = host
}

func ReCreateHTTP(port int, tcpIn chan<- C.ConnContext) {
	httpMux.Lock()
	defer httpMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Error().Err(err).Msg("[Inbound] HTTP server start failed")
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if httpListener != nil {
		if httpListener.RawAddress() == addr {
			return
		}
		_ = httpListener.Close()
		httpListener = nil
	}

	if portIsZero(addr) {
		return
	}

	httpListener, err = http.New(addr, tcpIn)
	if err != nil {
		return
	}

	log.Info().Str("addr", httpListener.Address()).Msg("[Inbound] HTTP proxy listening")
}

func ReCreateSocks(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	socksMux.Lock()
	defer socksMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Error().Err(err).Msg("[Inbound] SOCKS server start failed")
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if socksListener != nil {
		if socksListener.RawAddress() != addr {
			_ = socksListener.Close()
			socksListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}

	if socksUDPListener != nil {
		if socksUDPListener.RawAddress() != addr {
			_ = socksUDPListener.Close()
			socksUDPListener = nil
		} else {
			shouldUDPIgnore = true
		}
	}

	if shouldTCPIgnore && shouldUDPIgnore {
		return
	}

	if portIsZero(addr) {
		return
	}

	tcpListener, err := socks.New(addr, tcpIn)
	if err != nil {
		return
	}

	udpListener, err := socks.NewUDP(addr, udpIn)
	if err != nil {
		_ = tcpListener.Close()
		return
	}

	socksListener = tcpListener
	socksUDPListener = udpListener

	log.Info().Str("addr", socksListener.Address()).Msg("[Inbound] SOCKS proxy listening")
}

func ReCreateRedir(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	redirMux.Lock()
	defer redirMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Error().Err(err).Msg("[Inbound] Redirect server start failed")
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if redirListener != nil {
		if redirListener.RawAddress() == addr {
			return
		}
		_ = redirListener.Close()
		redirListener = nil
	}

	if redirUDPListener != nil {
		if redirUDPListener.RawAddress() == addr {
			return
		}
		_ = redirUDPListener.Close()
		redirUDPListener = nil
	}

	if portIsZero(addr) {
		return
	}

	redirListener, err = redir.New(addr, tcpIn)
	if err != nil {
		return
	}

	redirUDPListener, err = tproxy.NewUDP(addr, udpIn)
	if err != nil {
		log.Error().Err(err).Msg("[Inbound] Redirect UDP Listener failed")
	}

	log.Info().Str("addr", redirListener.Address()).Msg("[Inbound] Redirect proxy listening")
}

func ReCreateTProxy(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	tproxyMux.Lock()
	defer tproxyMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Error().Err(err).Msg("[Inbound] TProxy server start failed")
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if tproxyListener != nil {
		if tproxyListener.RawAddress() == addr {
			return
		}
		_ = tproxyListener.Close()
		tproxyListener = nil
	}

	if tproxyUDPListener != nil {
		if tproxyUDPListener.RawAddress() == addr {
			return
		}
		_ = tproxyUDPListener.Close()
		tproxyUDPListener = nil
	}

	if portIsZero(addr) {
		return
	}

	tproxyListener, err = tproxy.New(addr, tcpIn)
	if err != nil {
		return
	}

	tproxyUDPListener, err = tproxy.NewUDP(addr, udpIn)
	if err != nil {
		log.Error().Err(err).Msg("[Inbound] TProxy UDP Listener failed")
	}

	log.Info().Str("addr", tproxyListener.Address()).Msg("[Inbound] TProxy proxy listening")
}

func ReCreateMixed(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	mixedMux.Lock()
	defer mixedMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Error().Err(err).Msg("[Inbound] Mixed(http+socks) server start failed")
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if mixedListener != nil {
		if mixedListener.RawAddress() != addr {
			_ = mixedListener.Close()
			mixedListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}
	if mixedUDPLister != nil {
		if mixedUDPLister.RawAddress() != addr {
			_ = mixedUDPLister.Close()
			mixedUDPLister = nil
		} else {
			shouldUDPIgnore = true
		}
	}

	if shouldTCPIgnore && shouldUDPIgnore {
		return
	}

	if portIsZero(addr) {
		return
	}

	mixedListener, err = mixed.New(addr, tcpIn)
	if err != nil {
		return
	}

	mixedUDPLister, err = socks.NewUDP(addr, udpIn)
	if err != nil {
		_ = mixedListener.Close()
		return
	}

	log.Info().Str("addr", mixedListener.Address()).Msg("[Inbound] Mixed(http+socks) proxy listening")
}

func ReCreateTun(tunConf *config.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	tunMux.Lock()
	defer tunMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Error().Err(err).Msg("[Inbound] TUN server start failed")
		}
	}()

	tunConf.DNSHijack = lo.UniqBy(tunConf.DNSHijack, func(item C.DNSUrl) string {
		return item.String()
	})

	if tunStackListener != nil {
		if !hasTunConfigChange(tunConf) {
			return
		}

		_ = tunStackListener.Close()
		tunStackListener = nil
	}

	lastTunConf = tunConf

	if !tunConf.Enable {
		return
	}

	callback := &tunChangeCallback{
		tunConf: *tunConf,
		tcpIn:   tcpIn,
		udpIn:   udpIn,
	}

	tunStackListener, err = tun.New(tunConf, tcpIn, udpIn, callback)
	if err != nil {
		return
	}
}

func ReCreateMitm(port int, tcpIn chan<- C.ConnContext) {
	mitmMux.Lock()
	defer mitmMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Error().Err(err).Msg("[Inbound] MITM server start failed")
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if mitmListener != nil {
		if mitmListener.RawAddress() == addr {
			return
		}
		_ = mitmListener.Close()
		mitmListener = nil
		T.SetMitmOutbound(nil)
	}

	if portIsZero(addr) {
		return
	}

	if err = initCert(); err != nil {
		return
	}

	var (
		rootCACert tls.Certificate
		x509c      *x509.Certificate
		certOption *cert.Config
	)

	rootCACert, err = tls.LoadX509KeyPair(C.Path.RootCA(), C.Path.CAKey())
	if err != nil {
		return
	}

	privateKey := rootCACert.PrivateKey.(*rsa.PrivateKey)

	x509c, err = x509.ParseCertificate(rootCACert.Certificate[0])
	if err != nil {
		return
	}

	certOption, err = cert.NewConfig(
		x509c,
		privateKey,
	)
	if err != nil {
		return
	}

	certOption.SetValidity(time.Hour * 24 * 365 * 2) // 2 years
	certOption.SetOrganization("Clash ManInTheMiddle Proxy Services")

	opt := &mitm.Option{
		Addr:       addr,
		ApiHost:    "mitm.clash",
		CertConfig: certOption,
		Handler:    &rewrites.RewriteHandler{},
	}

	mitmListener, err = mitm.New(opt, tcpIn)
	if err != nil {
		return
	}

	T.SetMitmOutbound(outbound.NewMitm(mitmListener.Address()))

	log.Info().Str("addr", mitmListener.Address()).Msg("[Inbound] MITM proxy listening")
}

func ReCreateRedirToTun(ifaceNames []string) {
	tcMux.Lock()
	defer tcMux.Unlock()

	nicArr := lo.Uniq(ifaceNames)

	if tcProgram != nil {
		tcProgram.Close()
		tcProgram = nil
	}

	if len(nicArr) == 0 {
		return
	}

	if lastTunConf == nil || !lastTunConf.Enable {
		return
	}

	program, err := ebpf.NewTcEBpfProgram(nicArr, lastTunConf.Device)
	if err != nil {
		log.Error().Err(err).Msg("[Inbound] Attached tc ebpf program failed")
		return
	}
	tcProgram = program

	log.Info().Strs("interfaces", tcProgram.RawNICs()).Msg("[Inbound] Attached tc ebpf program")
}

func ReCreateAutoRedir(ifaceNames []string, defaultInterface string, tcpIn chan<- C.ConnContext, _ chan<- *inbound.PacketAdapter) {
	autoRedirMux.Lock()
	defer autoRedirMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			if redirListener != nil {
				_ = redirListener.Close()
				redirListener = nil
			}
			if autoRedirProgram != nil {
				autoRedirProgram.Close()
				autoRedirProgram = nil
			}
			log.Error().Err(err).Msg("[Inbound] Auto redirect server start failed")
		}
	}()

	nicArr := lo.Uniq(ifaceNames)
	defaultRouteInterfaceName := defaultInterface

	if autoRedirListener != nil && autoRedirProgram != nil {
		if defaultRouteInterfaceName == "" {
			defaultRouteInterfaceName, _ = commons.GetAutoDetectInterface()
		}
		if autoRedirProgram.RawInterface() == defaultRouteInterfaceName &&
			len(autoRedirProgram.RawNICs()) == len(nicArr) &&
			lo.Every(autoRedirProgram.RawNICs(), nicArr) {
			return
		}
		_ = autoRedirListener.Close()
		autoRedirProgram.Close()
		autoRedirListener = nil
		autoRedirProgram = nil
	}

	if len(nicArr) == 0 {
		return
	}

	if defaultRouteInterfaceName == "" {
		defaultRouteInterfaceName, err = commons.GetAutoDetectInterface()
		if err != nil {
			return
		}
	}

	addr := genAddr("*", C.TcpAutoRedirPort, true)

	autoRedirListener, err = autoredir.New(addr, tcpIn)
	if err != nil {
		return
	}

	autoRedirProgram, err = ebpf.NewRedirEBpfProgram(nicArr, autoRedirListener.TCPAddr().Port(),
		defaultRouteInterfaceName)

	if err != nil {
		return
	}

	autoRedirListener.SetLookupFunc(autoRedirProgram.Lookup)

	log.Info().
		Str("addr", autoRedirListener.Address()).
		Strs("interfaces", autoRedirProgram.RawNICs()).
		Msg("[Inbound] Auto redirect proxy listening, attached tc ebpf program")
}

func PatchTunnel(tunnels []config.Tunnel, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	tunnelMux.Lock()
	defer tunnelMux.Unlock()

	type addrProxy struct {
		network string
		addr    string
		target  string
		proxy   string
	}

	tcpOld := lo.Map(
		lo.Keys(tunnelTCPListeners),
		func(key string, _ int) addrProxy {
			parts := strings.Split(key, "/")
			return addrProxy{
				network: "tcp",
				addr:    parts[0],
				target:  parts[1],
				proxy:   parts[2],
			}
		},
	)
	udpOld := lo.Map(
		lo.Keys(tunnelUDPListeners),
		func(key string, _ int) addrProxy {
			parts := strings.Split(key, "/")
			return addrProxy{
				network: "udp",
				addr:    parts[0],
				target:  parts[1],
				proxy:   parts[2],
			}
		},
	)
	oldElm := lo.Union(tcpOld, udpOld)

	newElm := lo.FlatMap(
		tunnels,
		func(tunnel config.Tunnel, _ int) []addrProxy {
			return lo.Map(
				tunnel.Network,
				func(network string, _ int) addrProxy {
					return addrProxy{
						network: network,
						addr:    tunnel.Address,
						target:  tunnel.Target,
						proxy:   tunnel.Proxy,
					}
				},
			)
		},
	)

	needClose, needCreate := lo.Difference(oldElm, newElm)

	for _, elm := range needClose {
		key := fmt.Sprintf("%s/%s/%s", elm.addr, elm.target, elm.proxy)
		if elm.network == "tcp" {
			_ = tunnelTCPListeners[key].Close()
			delete(tunnelTCPListeners, key)
		} else {
			_ = tunnelUDPListeners[key].Close()
			delete(tunnelUDPListeners, key)
		}
	}

	for _, elm := range needCreate {
		key := fmt.Sprintf("%s/%s/%s", elm.addr, elm.target, elm.proxy)
		if elm.network == "tcp" {
			l, err := tunnel.New(elm.addr, elm.target, elm.proxy, tcpIn)
			if err != nil {
				log.Error().Err(err).Str("target", elm.target).Msg("[Inbound] Tunnel server start failed")
				continue
			}
			tunnelTCPListeners[key] = l
			log.Info().
				Str("addr", tunnelTCPListeners[key].Address()).
				Str("network", elm.network).
				Str("target", elm.target).
				Str("proxy", elm.proxy).
				Msg("[Inbound] Tunnel proxy listening")
		} else {
			l, err := tunnel.NewUDP(elm.addr, elm.target, elm.proxy, udpIn)
			if err != nil {
				log.Error().Err(err).Str("target", elm.target).Msg("[Inbound] Tunnel server start failed")
				continue
			}
			tunnelUDPListeners[key] = l
			log.Info().
				Str("addr", tunnelUDPListeners[key].Address()).
				Str("network", elm.network).
				Str("target", elm.target).
				Str("proxy", elm.proxy).
				Msg("[Inbound] Tunnel proxy listening")
		}
	}
}

// GetPorts return the ports of proxy servers
func GetPorts() *Ports {
	ports := &Ports{}

	if httpListener != nil {
		_, portStr, _ := net.SplitHostPort(httpListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.Port = port
	}

	if socksListener != nil {
		_, portStr, _ := net.SplitHostPort(socksListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.SocksPort = port
	}

	if redirListener != nil {
		_, portStr, _ := net.SplitHostPort(redirListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.RedirPort = port
	}

	if tproxyListener != nil {
		_, portStr, _ := net.SplitHostPort(tproxyListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.TProxyPort = port
	}

	if mixedListener != nil {
		_, portStr, _ := net.SplitHostPort(mixedListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.MixedPort = port
	}

	if mitmListener != nil {
		_, portStr, _ := net.SplitHostPort(mitmListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.MitmPort = port
	}

	return ports
}

func portIsZero(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if port == "0" || port == "" || err != nil {
		return true
	}
	return false
}

func genAddr(host string, port int, allowLan bool) string {
	if allowLan {
		if host == "*" {
			return fmt.Sprintf(":%d", port)
		}
		return fmt.Sprintf("%s:%d", host, port)
	}

	return fmt.Sprintf("127.0.0.1:%d", port)
}

func hasTunConfigChange(tunConf *config.Tun) bool {
	if lastTunConf == nil {
		return true
	}

	if len(lastTunConf.DNSHijack) != len(tunConf.DNSHijack) || !lo.Every(lastTunConf.DNSHijack, tunConf.DNSHijack) {
		return true
	}

	if lastTunConf.Enable != tunConf.Enable ||
		lastTunConf.Stack != tunConf.Stack ||
		lastTunConf.AutoRoute != tunConf.AutoRoute ||
		lastTunConf.AutoDetectInterface != tunConf.AutoDetectInterface {
		return true
	}

	if (lastTunConf.TunAddressPrefix != nil && tunConf.TunAddressPrefix == nil) ||
		(lastTunConf.TunAddressPrefix == nil && tunConf.TunAddressPrefix != nil) {
		return true
	}

	if lastTunConf.TunAddressPrefix != nil && tunConf.TunAddressPrefix != nil &&
		*lastTunConf.TunAddressPrefix != *tunConf.TunAddressPrefix {
		return true
	}

	return false
}

type tunChangeCallback struct {
	tunConf config.Tun
	tcpIn   chan<- C.ConnContext
	udpIn   chan<- *inbound.PacketAdapter
}

func (t *tunChangeCallback) Pause() {
	conf := t.tunConf
	conf.Enable = false
	ReCreateTun(&conf, t.tcpIn, t.udpIn)
	ReCreateRedirToTun([]string{})
}

func (t *tunChangeCallback) Resume() {
	conf := t.tunConf
	conf.Enable = true
	ReCreateTun(&conf, t.tcpIn, t.udpIn)
	ReCreateRedirToTun(conf.RedirectToTun)
}

func initCert() error {
	if _, err := os.Stat(C.Path.RootCA()); os.IsNotExist(err) {
		log.Info().Msg("[Config] Can't find mitm_ca.crt, start generate")
		err = cert.GenerateAndSave(C.Path.RootCA(), C.Path.CAKey())
		if err != nil {
			return err
		}
		log.Info().Msg("[Config] Generated CA private key and CA certificate finish")
	}

	return nil
}

func Cleanup() {
	if tcProgram != nil {
		tcProgram.Close()
	}
	if autoRedirProgram != nil {
		autoRedirProgram.Close()
	}
	if tunStackListener != nil {
		_ = tunStackListener.Close()
	}
}
