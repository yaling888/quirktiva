package outbound

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/phuslu/log"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/wireguard"
)

type WireGuard struct {
	*Base
	wgDevice  *device.Device
	tunDevice tun.Device
	netStack  *netstack.Net
	bind      *wireguard.WgBind
	dialer    *wgDialer
	endpoint  netip.AddrPort
	upOnce    sync.Once
	closeOnce sync.Once
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
	w.dialer.options = opts

	c, err := w.netStack.DialContext(ctx, "tcp", metadata.RemoteAddress())
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
		w.tunDevice.Events() <- tun.EventUp
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

	localDialer := &wgDialer{}
	wgBind := wireguard.NewWgBind(context.Background(), localDialer, endpoint)

	tunDevice, netStack, err := netstack.CreateNetTUN(localIPs, dnsServers, mtu)
	if err != nil {
		return nil, fmt.Errorf("create wireguard device failure, cause: %w", err)
	}

	wgDevice := device.NewDevice(tunDevice, wgBind, &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Debug().Msgf("[WireGuard] "+strings.ToLower(format), args...)
		},
		Errorf: func(format string, args ...any) {
			log.Error().Msgf("[WireGuard] "+strings.ToLower(format), args...)
		},
	})

	log.Info().Strs("config", uapiConf).Msg("[Config] initial wireguard")

	err = wgDevice.IpcSet(strings.Join(uapiConf, "\n"))
	if err != nil {
		return nil, fmt.Errorf("initial wireguard failure, cause: %w", err)
	}

	wireGuard := &WireGuard{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.WireGuard,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		bind:      wgBind,
		wgDevice:  wgDevice,
		tunDevice: tunDevice,
		netStack:  netStack,
		endpoint:  endpoint,
		dialer:    localDialer,
	}
	runtime.SetFinalizer(wireGuard, wgCloser)
	return wireGuard, nil
}

var wgCloser = func(w *WireGuard) {
	w.closeOnce.Do(func() {
		if w.wgDevice != nil {
			w.wgDevice.Close()
		}
		if w.tunDevice != nil {
			_ = w.tunDevice.Close()
		}
	})
}
