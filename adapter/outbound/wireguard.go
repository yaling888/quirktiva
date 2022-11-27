package outbound

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phuslu/log"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/wireguard"
)

const dialTimeout = 8 * time.Second

type WireGuard struct {
	*Base
	wgDevice  *device.Device
	tunDevice tun.Device
	netStack  *netstack.Net
	bind      *wireguard.WgBind

	dialer     *wgDialer
	endpoint   netip.AddrPort
	localIPs   []netip.Addr
	dnsServers []netip.Addr
	uapiConf   []string
	threadId   string
	mtu        int

	upOnce   sync.Once
	downOnce sync.Once
	upErr    error
}

type WireGuardOption struct {
	BasicOption
	Name         string   `proxy:"name"`
	Server       string   `proxy:"server"`
	Port         int      `proxy:"port"`
	IP           string   `proxy:"ip,omitempty"`
	IPv6         string   `proxy:"ipv6,omitempty"`
	PrivateKey   string   `proxy:"private-key"`
	PublicKey    string   `proxy:"public-key"`
	PresharedKey string   `proxy:"preshared-key,omitempty"`
	DNS          []string `proxy:"dns,omitempty"`
	MTU          int      `proxy:"mtu,omitempty"`
	UDP          bool     `proxy:"udp,omitempty"`
}

func (w *WireGuard) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	w.up()
	if w.upErr != nil {
		return nil, fmt.Errorf("apply wireguard proxy %s config failure, cause: %w", w.threadId, w.upErr)
	}
	w.dialer.options = opts

	dialCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithDeadline(ctx, time.Now().Add(dialTimeout))
		defer cancel()
	}

	c, err := w.netStack.DialContext(dialCtx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("conn is nil")
	}
	return NewConn(c, w), nil
}

func (w *WireGuard) ListenPacketContext(_ context.Context, _ *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	w.up()
	if w.upErr != nil {
		return nil, fmt.Errorf("apply wireguard proxy %s config failure, cause: %w", w.threadId, w.upErr)
	}
	w.dialer.options = opts

	pc, err := w.netStack.ListenUDPAddrPort(w.endpoint)
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, errors.New("packetConn is nil")
	}
	return NewPacketConn(pc, w), nil
}

func (w *WireGuard) up() {
	w.upOnce.Do(func() {
		w.upErr = initWireGuard(w)
	})
}

func (w *WireGuard) down() {
	w.downOnce.Do(func() {
		if w.wgDevice != nil {
			w.wgDevice.Close()
		}
	})
}

type wgDialer struct {
	options []dialer.Option
}

func (d *wgDialer) DialContext(ctx context.Context, network string, address netip.AddrPort) (net.Conn, error) {
	return dialer.DialContext(ctx, network, address.String(), d.options...)
}

func (d *wgDialer) ListenPacket(ctx context.Context, _ netip.AddrPort) (net.PacketConn, error) {
	return dialer.ListenPacket(ctx, "udp", "", d.options...)
}

func NewWireGuard(option WireGuardOption) (*WireGuard, error) {
	uapiConf := make([]string, 0, 6)
	privateKeyBytes, err := base64.StdEncoding.DecodeString(option.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode wireguard private key failure, cause: %w", err)
	}
	uapiConf = append(uapiConf, fmt.Sprintf("private_key=%s", hex.EncodeToString(privateKeyBytes)))

	publicKeyBytes, err := base64.StdEncoding.DecodeString(option.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode wireguard peer public key failure, cause: %w", err)
	}
	uapiConf = append(uapiConf, fmt.Sprintf("public_key=%s", hex.EncodeToString(publicKeyBytes)))

	if option.PresharedKey != "" {
		bytes, err := base64.StdEncoding.DecodeString(option.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("decode wireguard preshared key failure, cause: %w", err)
		}
		uapiConf = append(uapiConf, fmt.Sprintf("preshared_key=%s", hex.EncodeToString(bytes)))
	}

	endpointIP, err := resolver.ResolveProxyServerHost(option.Server)
	if err != nil {
		return nil, fmt.Errorf("parse wireguard server endpoint [%s] failure, cause: %w", option.Server, err)
	}
	endpoint := netip.AddrPortFrom(endpointIP, uint16(option.Port))
	uapiConf = append(uapiConf, fmt.Sprintf("endpoint=%s", endpoint))

	localIPs := make([]netip.Addr, 0, 2)
	if option.IP != "" {
		if ip, err1 := netip.ParseAddr(option.IP); err1 != nil {
			return nil, fmt.Errorf("parse wireguard ip address failure, cause: %w", err1)
		} else {
			localIPs = append(localIPs, ip)
		}
	}

	if option.IPv6 != "" {
		if ip, err1 := netip.ParseAddr(option.IPv6); err1 != nil {
			return nil, fmt.Errorf("parse wireguard ipv6 address failure, cause: %w", err1)
		} else {
			localIPs = append(localIPs, ip)
		}
	}

	if len(localIPs) == 0 {
		return nil, errors.New("wireguard missing local ip")
	}

	dns := option.DNS
	if len(dns) == 0 {
		dns = append(dns, "1.1.1.1")
	}
	dnsServers := make([]netip.Addr, len(dns))
	for _, d := range dns {
		if ip, err1 := netip.ParseAddr(d); err1 != nil {
			return nil, fmt.Errorf("parse wireguard dns address failure, cause: %w", err1)
		} else {
			dnsServers = append(dnsServers, ip)
		}
	}

	var (
		hasIP4 bool
		hasIP6 bool
	)
	for _, ip := range localIPs {
		if ip.Is4() {
			hasIP4 = true
		} else {
			hasIP6 = true
		}
	}

	if hasIP4 {
		uapiConf = append(uapiConf, "allowed_ip=0.0.0.0/0")
	}
	if hasIP6 {
		uapiConf = append(uapiConf, "allowed_ip=::/0")
	}

	mtu := option.MTU
	if mtu == 0 {
		mtu = 1408
	}

	threadId := fmt.Sprintf("%s-%d", option.Name, rand.Intn(100))

	wireGuard := &WireGuard{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.WireGuard,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		dialer:     &wgDialer{},
		endpoint:   endpoint,
		localIPs:   localIPs,
		dnsServers: dnsServers,
		uapiConf:   uapiConf,
		threadId:   threadId,
		mtu:        mtu,
	}
	return wireGuard, nil
}

func initWireGuard(wg *WireGuard) error {
	wgBind := wireguard.NewWgBind(context.Background(), wg.dialer, wg.endpoint)

	tunDevice, netStack, err := netstack.CreateNetTUN(wg.localIPs, wg.dnsServers, wg.mtu)
	if err != nil {
		return fmt.Errorf("initial wireguard proxy %s failure, cause: %w", wg.threadId, err)
	}

	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Debug().Msgf("[WireGuard] [%s] "+strings.ToLower(format), append([]any{wg.threadId}, args...)...)
		},
		Errorf: func(format string, args ...any) {
			log.Error().Msgf("[WireGuard] [%s] "+strings.ToLower(format), append([]any{wg.threadId}, args...)...)
		},
	}

	wgDevice := device.NewDevice(tunDevice, wgBind, logger)

	log.Debug().Strs("config", wg.uapiConf).Msg("[WireGuard] initial wireguard")

	err = wgDevice.IpcSet(strings.Join(wg.uapiConf, "\n"))
	if err != nil {
		return fmt.Errorf("initial wireguard proxy %s failure, cause: %w", wg.threadId, err)
	}

	wg.bind = wgBind
	wg.tunDevice = tunDevice
	wg.netStack = netStack
	wg.wgDevice = wgDevice

	runtime.SetFinalizer(wg, func(w *WireGuard) {
		w.down()
	})
	return nil
}
