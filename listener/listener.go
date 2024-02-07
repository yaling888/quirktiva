package listener

import (
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/phuslu/log"
	"github.com/samber/lo"

	"github.com/yaling888/clash/adapter/inbound"
	"github.com/yaling888/clash/component/dialer"
	"github.com/yaling888/clash/component/ebpf"
	"github.com/yaling888/clash/component/iface"
	"github.com/yaling888/clash/config"
	C "github.com/yaling888/clash/constant"
	A "github.com/yaling888/clash/listener/auth"
	"github.com/yaling888/clash/listener/autoredir"
	"github.com/yaling888/clash/listener/http"
	"github.com/yaling888/clash/listener/mitm"
	"github.com/yaling888/clash/listener/mixed"
	"github.com/yaling888/clash/listener/redir"
	"github.com/yaling888/clash/listener/socks"
	"github.com/yaling888/clash/listener/tproxy"
	"github.com/yaling888/clash/listener/tun"
	"github.com/yaling888/clash/listener/tun/ipstack"
	"github.com/yaling888/clash/listener/tun/ipstack/commons"
	"github.com/yaling888/clash/listener/tunnel"
	"github.com/yaling888/clash/tunnel/statistic"
)

var (
	allowLan    = false
	bindAddress = "*"

	tcpInbounds  = map[string]C.Inbound{}
	udpInbounds  = map[string]C.Inbound{}
	tcpListeners = map[string]C.Listener{}
	udpListeners = map[string]C.Listener{}

	tunStackListener  ipstack.Stack
	tcProgram         *ebpf.TcEBpfProgram
	autoRedirListener *autoredir.Listener
	autoRedirProgram  *ebpf.TcEBpfProgram

	tunnelTCPListeners = map[string]*tunnel.Listener{}
	tunnelUDPListeners = map[string]*tunnel.PacketConn{}

	// lock for recreate function
	inboundsMux  sync.Mutex
	tunMux       sync.Mutex
	tcMux        sync.Mutex
	autoRedirMux sync.Mutex
	tunnelMux    sync.Mutex
)

var tcpListenerCreators = map[C.InboundType]tcpListenerCreator{
	C.InboundTypeHTTP:   http.New,
	C.InboundTypeSocks:  socks.New,
	C.InboundTypeSocks4: socks.New4,
	C.InboundTypeSocks5: socks.New5,
	C.InboundTypeRedir:  redir.New,
	C.InboundTypeTproxy: tproxy.New,
	C.InboundTypeMixed:  mixed.New,
	C.InboundTypeMitm:   mitm.New,
}

var udpListenerCreators = map[C.InboundType]udpListenerCreator{
	C.InboundTypeSocks:  socks.NewUDP,
	C.InboundTypeSocks5: socks.NewUDP,
	C.InboundTypeRedir:  tproxy.NewUDP,
	C.InboundTypeTproxy: tproxy.NewUDP,
	C.InboundTypeMixed:  socks.NewUDP,
}

type (
	tcpListenerCreator func(addr string, tcpIn chan<- C.ConnContext) (C.Listener, error)
	udpListenerCreator func(addr string, udpIn chan<- *inbound.PacketAdapter) (C.Listener, error)
)

type Ports struct {
	Port       int `json:"port"`
	SocksPort  int `json:"socks-port"`
	RedirPort  int `json:"redir-port"`
	TProxyPort int `json:"tproxy-port"`
	MixedPort  int `json:"mixed-port"`
	MitmPort   int `json:"mitm-port"`
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

func createListener(inbound C.Inbound, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	addr := inbound.BindAddress
	if portIsZero(addr) {
		log.Error().Str("addr", addr).Msgf("[Inbound] invalid %s address", inbound.Type)
		return
	}

	inboundKey := inbound.Key()
	tcpCreator := tcpListenerCreators[inbound.Type]
	udpCreator := udpListenerCreators[inbound.Type]

	if tcpCreator == nil && udpCreator == nil {
		log.Error().Str("addr", addr).Msgf("[Inbound] server type %s is not supported", inbound.Type)
		return
	}

	au := "none"
	auLen := len(lo.FromPtr(inbound.Authentication))
	if auLen != 0 {
		au = "local"
	} else if A.Authenticator() != nil {
		au = "global"
	}
	if inbound.Type == C.InboundTypeRedir || inbound.Type == C.InboundTypeTproxy {
		au = "none"
	}

	if tcpCreator != nil {
		tcpListener, err := tcpCreator(addr, tcpIn)
		if err != nil {
			log.Error().Err(err).Str("addr", addr).Msgf("[Inbound] %s tcp server start failed", inbound.Type)
			return
		}

		if !inbound.IsFromPortCfg && auLen != 0 {
			if tl, ok := tcpListener.(C.AuthenticatorListener); ok {
				authUsers := config.ParseAuthentication(*inbound.Authentication)
				tl.SetAuthenticator(authUsers)
			}
		}

		tcpInbounds[inboundKey] = inbound
		tcpListeners[inboundKey] = tcpListener

		log.Info().
			Str("addr", addr).
			Str("network", "tcp").
			Str("auth", au).
			Msgf("[Inbound] %s proxy listening", inbound.Type)
	}

	if udpCreator != nil {
		udpListener, err := udpCreator(addr, udpIn)
		if err != nil {
			log.Error().Err(err).Str("addr", addr).Msgf("[Inbound] %s udp server start failed", inbound.Type)
			return
		}

		udpInbounds[inboundKey] = inbound
		udpListeners[inboundKey] = udpListener

		log.Info().
			Str("addr", addr).
			Str("network", "udp").
			Str("auth", au).
			Msgf("[Inbound] %s proxy listening", inbound.Type)
	}
}

func closeListener(inbound C.Inbound) {
	inboundKey := inbound.Key()
	listener := tcpListeners[inboundKey]
	if listener != nil {
		if err := listener.Close(); err != nil {
			log.Error().Err(err).Msgf("[Inbound] close tcp server `%s` failed", inbound.ToAlias())
		}
		delete(tcpInbounds, inboundKey)
		delete(tcpListeners, inboundKey)
		log.Info().
			Str("addr", inbound.BindAddress).
			Str("network", "tcp").
			Msgf("[Inbound] %s proxy is down", inbound.Type)
	}
	listener = udpListeners[inboundKey]
	if listener != nil {
		if err := listener.Close(); err != nil {
			log.Error().Err(err).Msgf("[Inbound] close udp server `%s` failed", inbound.ToAlias())
		}
		delete(udpInbounds, inboundKey)
		delete(udpListeners, inboundKey)
		log.Info().
			Str("addr", inbound.BindAddress).
			Str("network", "udp").
			Msgf("[Inbound] %s proxy is down", inbound.Type)
	}
}

func getNeedCloseAndCreateInbound(originInbounds []C.Inbound, newInbounds []C.Inbound) ([]C.Inbound, []C.Inbound) {
	var (
		needClose    []C.Inbound
		needCreate   []C.Inbound
		needCloseMap = make(map[string]C.Inbound)
	)
	for _, m := range originInbounds {
		needCloseMap[m.Key()] = m
	}
	for _, m := range newInbounds {
		key := m.Key()
		if c, ok := needCloseMap[key]; ok {
			if !reflect.DeepEqual(m.Authentication, c.Authentication) {
				needCreate = append(needCreate, m)
			} else {
				delete(needCloseMap, key)
			}
		} else {
			needCreate = append(needCreate, m)
		}
	}
	for _, m := range needCloseMap {
		needClose = append(needClose, m)
	}
	return needClose, needCreate
}

// ReCreateListeners only recreate inbound config listener
func ReCreateListeners(inbounds []C.Inbound, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	inboundsMux.Lock()
	defer inboundsMux.Unlock()
	newInbounds := append([]C.Inbound{}, inbounds...)
	for _, m := range getInbounds() {
		if m.IsFromPortCfg {
			newInbounds = append(newInbounds, m)
		}
	}
	reCreateListeners(newInbounds, tcpIn, udpIn)
}

// ReCreatePortsListeners only recreate ports config listener
func ReCreatePortsListeners(ports Ports, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	inboundsMux.Lock()
	defer inboundsMux.Unlock()
	newInbounds := addPortInbound([]C.Inbound{}, C.InboundTypeHTTP, ports.Port)
	newInbounds = addPortInbound(newInbounds, C.InboundTypeSocks, ports.SocksPort)
	newInbounds = addPortInbound(newInbounds, C.InboundTypeRedir, ports.RedirPort)
	newInbounds = addPortInbound(newInbounds, C.InboundTypeTproxy, ports.TProxyPort)
	newInbounds = addPortInbound(newInbounds, C.InboundTypeMixed, ports.MixedPort)
	newInbounds = addPortInbound(newInbounds, C.InboundTypeMitm, ports.MitmPort)
	newInbounds = append(newInbounds, GetInbounds()...)
	reCreateListeners(newInbounds, tcpIn, udpIn)
}

func addPortInbound(inbounds []C.Inbound, inboundType C.InboundType, port int) []C.Inbound {
	if port != 0 {
		inbounds = append(inbounds, C.Inbound{
			Type:          inboundType,
			BindAddress:   genAddr(bindAddress, port, allowLan),
			IsFromPortCfg: true,
		})
	}
	return inbounds
}

func reCreateListeners(inbounds []C.Inbound, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	needClose, needCreate := getNeedCloseAndCreateInbound(getInbounds(), inbounds)
	for _, m := range needClose {
		closeListener(m)
	}
	for _, m := range needCreate {
		createListener(m, tcpIn, udpIn)
	}
	C.SetProxyInbound(tcpInbounds)
}

func ReCreateTun(tunConf *C.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	tunMux.Lock()
	defer tunMux.Unlock()

	if C.IsNoGVisor {
		tunConf.Stack = C.TunSystem
	}

	tunConf.DNSHijack = lo.UniqBy(tunConf.DNSHijack, func(item C.DNSUrl) string {
		return item.String()
	})

	if tunStackListener != nil {
		if !hasTunConfigChange(tunConf) {
			return
		}

		if tunConf.StopRouteListener && !tunConf.Enable {
			commons.SetTunStatus(C.TunDisabled)
		}

		_ = tunStackListener.Close()
		tunStackListener = nil
	}

	C.SetLastTunConf(tunConf)

	if !tunConf.Enable {
		return
	}

	callback := &tunChangeCallback{
		tunConf: *tunConf,
		tcpIn:   tcpIn,
		udpIn:   udpIn,
	}

	if tunConf.AutoDetectInterface {
		outboundInterface, err := commons.GetAutoDetectInterface()
		if err != nil {
			log.Info().Err(err).Msg("[Tun] auto detect interface failed")
		}
		if outboundInterface != "" && outboundInterface != dialer.DefaultInterface.Load() {
			dialer.DefaultInterface.Store(outboundInterface)
			iface.FlushCache()
			commons.UpdateWireGuardBind()
			log.Info().
				Str("name", outboundInterface).
				Msg("[TUN] default interface has overwrite by auto detect interface")
		}
	}

	var err error
	tunStackListener, err = tun.New(tunConf, tcpIn, udpIn, callback)
	if err != nil {
		log.Error().Err(err).Msg("[Inbound] tun server start failed")
	}
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

	lastTunConf := C.GetLastTunConf()
	if lastTunConf == nil || !lastTunConf.Enable {
		return
	}

	program, err := ebpf.NewTcEBpfProgram(nicArr, lastTunConf.Device)
	if err != nil {
		log.Error().Err(err).Msg("[Inbound] attach tc ebpf program failed")
		return
	}
	tcProgram = program

	log.Info().Strs("interfaces", tcProgram.RawNICs()).Msg("[Inbound] attached tc ebpf program")
}

func ReCreateAutoRedir(ifaceNames []string, defaultInterface string, tcpIn chan<- C.ConnContext, _ chan<- *inbound.PacketAdapter) {
	autoRedirMux.Lock()
	defer autoRedirMux.Unlock()

	var err error
	defer func(err error) {
		if err != nil {
			if autoRedirListener != nil {
				_ = autoRedirListener.Close()
				autoRedirListener = nil
			}
			if autoRedirProgram != nil {
				autoRedirProgram.Close()
				autoRedirProgram = nil
			}
			log.Error().Err(err).Msg("[Inbound] auto redirect server start failed")
		}
	}(err)

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
		Msg("[Inbound] auto redirect proxy listening, attached tc ebpf program")
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
				log.Error().Err(err).Str("target", elm.target).Msg("[Inbound] tunnel server start failed")
				continue
			}
			tunnelTCPListeners[key] = l
			log.Info().
				Str("addr", tunnelTCPListeners[key].Address()).
				Str("network", elm.network).
				Str("target", elm.target).
				Str("proxy", elm.proxy).
				Msg("[Inbound] tunnel proxy listening")
		} else {
			l, err := tunnel.NewUDP(elm.addr, elm.target, elm.proxy, udpIn)
			if err != nil {
				log.Error().Err(err).Str("target", elm.target).Msg("[Inbound] tunnel server start failed")
				continue
			}
			tunnelUDPListeners[key] = l
			log.Info().
				Str("addr", tunnelUDPListeners[key].Address()).
				Str("network", elm.network).
				Str("target", elm.target).
				Str("proxy", elm.proxy).
				Msg("[Inbound] tunnel proxy listening")
		}
	}
}

func GetInbounds() []C.Inbound {
	return lo.Filter(getInbounds(), func(inbound C.Inbound, _ int) bool {
		return !inbound.IsFromPortCfg
	})
}

// GetInbounds return inbounds of proxy servers
func getInbounds() []C.Inbound {
	var inbounds []C.Inbound
	for _, tcp := range tcpInbounds {
		inbounds = append(inbounds, tcp)
	}
	for _, udp := range udpInbounds {
		if _, ok := tcpInbounds[udp.Key()]; !ok {
			inbounds = append(inbounds, udp)
		}
	}
	return inbounds
}

// GetPorts return the ports of proxy servers
func GetPorts() *Ports {
	ports := &Ports{}
	for _, m := range getInbounds() {
		fillPort(m, ports)
	}
	return ports
}

func fillPort(inbound C.Inbound, ports *Ports) {
	if inbound.IsFromPortCfg {
		port := getPort(inbound.BindAddress)
		switch inbound.Type {
		case C.InboundTypeHTTP:
			ports.Port = port
		case C.InboundTypeSocks:
			ports.SocksPort = port
		case C.InboundTypeTproxy:
			ports.TProxyPort = port
		case C.InboundTypeRedir:
			ports.RedirPort = port
		case C.InboundTypeMixed:
			ports.MixedPort = port
		case C.InboundTypeMitm:
			ports.MitmPort = port
		default:
			// do nothing
		}
	}
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

func getPort(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0
	}
	return int(port)
}

func hasTunConfigChange(tunConf *C.Tun) bool {
	lastTunConf := C.GetLastTunConf()
	if lastTunConf == nil {
		return true
	}

	if lastTunConf.Enable != tunConf.Enable ||
		lastTunConf.Stack != tunConf.Stack ||
		!lo.Every(lastTunConf.DNSHijack, tunConf.DNSHijack) ||
		lastTunConf.AutoRoute != tunConf.AutoRoute ||
		lastTunConf.AutoDetectInterface != tunConf.AutoDetectInterface ||
		!reflect.DeepEqual(lastTunConf.TunAddressPrefix, tunConf.TunAddressPrefix) {
		return true
	}

	return false
}

type tunChangeCallback struct {
	tunConf C.Tun
	tcpIn   chan<- C.ConnContext
	udpIn   chan<- *inbound.PacketAdapter
}

func (t *tunChangeCallback) Pause() {
	conf := t.tunConf
	conf.Enable = false
	conf.StopRouteListener = false
	ReCreateTun(&conf, t.tcpIn, t.udpIn)
	ReCreateRedirToTun([]string{})
}

func (t *tunChangeCallback) Resume() {
	conf := t.tunConf
	conf.Enable = true
	conf.StopRouteListener = false
	ReCreateTun(&conf, t.tcpIn, t.udpIn)
	ReCreateRedirToTun(conf.RedirectToTun)
	statistic.DefaultManager.Cleanup()
}

func Cleanup() {
	if tcProgram != nil {
		tcProgram.Close()
	}
	if autoRedirProgram != nil {
		autoRedirProgram.Close()
	}
	if tunStackListener != nil {
		commons.SetTunStatus(C.TunDisabled)
		_ = tunStackListener.Close()
	}
}
