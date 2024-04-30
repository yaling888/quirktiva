//go:build !nohy2

package outbound

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/client"
	"github.com/apernet/hysteria/extras/obfs"

	"github.com/yaling888/clash/common/pool"
	"github.com/yaling888/clash/component/dialer"
	"github.com/yaling888/clash/component/resolver"
	C "github.com/yaling888/clash/constant"
)

type Hysteria2Option struct {
	BasicOption
	Name             string `proxy:"name"`
	Server           string `proxy:"server"`
	Port             int    `proxy:"port"`
	Password         string `proxy:"password"`
	SkipCertVerify   bool   `proxy:"skip-cert-verify,omitempty"`
	SNI              string `proxy:"sni,omitempty"`
	PinSHA256        string `proxy:"pin-sha256,omitempty"`
	Obfs             string `proxy:"obfs,omitempty"`
	ObfsParam        string `proxy:"obfs-param,omitempty"`
	Up               string `proxy:"up,omitempty"`
	Down             string `proxy:"down,omitempty"`
	UDP              bool   `proxy:"udp,omitempty"`
	RemoteDnsResolve bool   `proxy:"remote-dns-resolve,omitempty"`
}

var _ C.ProxyAdapter = (*Hysteria2)(nil)

type Hysteria2 struct {
	*Base
	client client.Client
	lAddr  net.Addr
	option *Hysteria2Option

	closeOnce sync.Once
}

func (h *Hysteria2) DialContext(ctx context.Context, metadata *C.Metadata, _ ...dialer.Option) (C.Conn, error) {
	var (
		c    net.Conn
		err  error
		done = make(chan struct{})
	)
	go func() {
		host := metadata.Host
		if metadata.Resolved() {
			host = metadata.DstIP.String()
		}
		c, err = h.client.TCP(net.JoinHostPort(host, metadata.DstPort.String()))
		select {
		case <-ctx.Done():
			if c != nil {
				_ = c.Close()
			}
		default:
			close(done)
		}
	}()
	select {
	case <-done:
		if err != nil {
			return nil, err
		}
		return NewConn(c, h), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *Hysteria2) ListenPacketContext(ctx context.Context, _ *C.Metadata, _ ...dialer.Option) (C.PacketConn, error) {
	var (
		huc  client.HyUDPConn
		err  error
		done = make(chan struct{})
	)
	go func() {
		huc, err = h.client.UDP()
		select {
		case <-ctx.Done():
			if huc != nil {
				_ = huc.Close()
			}
		default:
			close(done)
		}
	}()
	select {
	case <-done:
		if err != nil {
			return nil, err
		}
		return NewPacketConn(&hysteria2PacketConn{
			conn:  huc,
			lAddr: h.lAddr,
			done:  make(chan struct{}),
		}, h), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *Hysteria2) Cleanup() {
	h.closeOnce.Do(func() {
		_ = h.client.Close()
	})
}

func (h *Hysteria2) makeDialer() func(addr net.Addr) (net.PacketConn, error) {
	return func(_ net.Addr) (net.PacketConn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
		defer cancel()
		pc, err := dialer.ListenPacket(ctx, "udp", "", h.Base.DialOptions([]dialer.Option{}...)...)
		if err == nil {
			h.lAddr = pc.LocalAddr()
		}
		return pc, err
	}
}

func NewHysteria2(option Hysteria2Option) (*Hysteria2, error) {
	var (
		ob  obfs.Obfuscator
		err error
	)
	switch strings.ToLower(option.Obfs) {
	case "", "plain":
	case "salamander":
		ob, err = obfs.NewSalamanderObfuscator([]byte(option.ObfsParam))
		if err != nil {
			return nil, fmt.Errorf("invalid obfs-param: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported obfs type: %s", option.Obfs)
	}

	var up, down uint64
	if option.Up != "" {
		if up, err = convBandwidth(option.Up); err != nil {
			return nil, fmt.Errorf("parse up failed: %w", err)
		}
	}
	if option.Down != "" {
		if down, err = convBandwidth(option.Down); err != nil {
			return nil, fmt.Errorf("parse down failed: %w", err)
		}
	}

	h := &Hysteria2{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Hysteria2,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
			dns:   option.RemoteDnsResolve,
		},
		option: &option,
	}

	dial := h.makeDialer()

	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	config := &client.Config{
		Auth: h.option.Password,
		ConnFactory: &adaptiveConnFactory{
			Dial:       dial,
			Obfuscator: ob,
		},
		TLSConfig: client.TLSConfig{
			ServerName:         serverName,
			InsecureSkipVerify: h.option.SkipCertVerify,
		},
		QUICConfig: client.QUICConfig{
			MaxIdleTimeout:  120 * time.Second,
			KeepAlivePeriod: 10 * time.Second,
		},
		BandwidthConfig: client.BandwidthConfig{
			MaxTx: up,
			MaxRx: down,
		},
	}

	if h.option.PinSHA256 != "" {
		nHash := normalizeCertHash(h.option.PinSHA256)
		config.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, cert := range rawCerts {
				hash := sha256.Sum256(cert)
				hashHex := hex.EncodeToString(hash[:])
				if hashHex == nHash {
					return nil
				}
			}
			// No match
			return errors.New("no certificate matches the pinned hash")
		}
	}

	cl, err := client.NewReconnectableClient(
		func() (*client.Config, error) {
			ip, err := resolver.ResolveProxyServerHost(h.option.Server)
			if err != nil {
				return nil, err
			}
			cfg := new(client.Config)
			*cfg = *config
			cfg.ServerAddr = &net.UDPAddr{IP: ip.AsSlice(), Port: h.option.Port}
			return cfg, nil
		},
		func(c client.Client, info *client.HandshakeInfo, count int) {
			if !h.Base.udp {
				h.Base.udp = info.UDPEnabled
			}
		},
		true,
	)
	if err != nil {
		return nil, err
	}

	h.client = cl
	return h, nil
}

type adaptiveConnFactory struct {
	Dial       func(addr net.Addr) (net.PacketConn, error)
	Obfuscator obfs.Obfuscator // nil if no obfuscation
}

func (f *adaptiveConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	if f.Obfuscator == nil {
		return f.Dial(addr)
	}
	c, err := f.Dial(addr)
	if err != nil {
		return nil, err
	}
	return obfs.WrapPacketConn(c, f.Obfuscator), nil
}

var _ net.PacketConn = (*hysteria2PacketConn)(nil)

type hysteria2PacketConn struct {
	conn  client.HyUDPConn
	lAddr net.Addr

	wMux    sync.Mutex
	rMux    sync.Mutex
	bufP    *pool.BufferWriter
	lasR    int
	lasAddr net.Addr

	closeOnce sync.Once

	done chan struct{}
	err  error

	mux      sync.Mutex
	deadline *time.Timer
}

func (hp *hysteria2PacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	hp.wMux.Lock()
	defer hp.wMux.Unlock()

	if hp.err != nil {
		return 0, hp.err
	}
	if err = hp.conn.Send(b, addr.String()); err == nil {
		n = len(b)
	}
	return
}

func (hp *hysteria2PacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	hp.rMux.Lock()
	defer hp.rMux.Unlock()

	if hp.err != nil {
		err = hp.err
		if hp.bufP != nil {
			pool.PutBufferWriter(hp.bufP)
			hp.bufP = nil
		}
		hp.lasAddr = nil
		hp.lasR = 0
		return
	}

	if hp.bufP != nil {
		n = copy(b, hp.bufP.Bytes()[hp.bufP.Len()-hp.lasR:])
		addr = hp.lasAddr
		hp.lasR -= n
		if hp.lasR == 0 {
			pool.PutBufferWriter(hp.bufP)
			hp.bufP = nil
			hp.lasAddr = nil
		}
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			buf, from, er := hp.conn.Receive()
			if er != nil {
				err = er
				return
			}
			nr := len(buf)
			if nr == 0 {
				continue
			}
			ap, er := netip.ParseAddrPort(from)
			if er != nil {
				continue
			}
			addr = net.UDPAddrFromAddrPort(ap)
			n = copy(b, buf)
			if n < nr {
				select {
				case <-hp.done:
					return
				default:
				}
				bufP := pool.GetBufferWriter()
				bufP.PutSlice(buf[n:])
				hp.bufP = bufP
				hp.lasAddr = addr
				hp.lasR = bufP.Len()
			}
			return
		}
	}()

	select {
	case <-done:
	case <-hp.done:
		err = context.DeadlineExceeded
	}
	return
}

func (hp *hysteria2PacketConn) Close() error {
	hp.err = net.ErrClosed
	hp.closeOnce.Do(func() {
		_ = hp.conn.Close()
	})
	return nil
}

func (hp *hysteria2PacketConn) LocalAddr() net.Addr {
	return hp.lAddr
}

func (hp *hysteria2PacketConn) SetDeadline(t time.Time) error {
	if hp.err != nil {
		return hp.err
	}
	hp.mux.Lock()
	defer hp.mux.Unlock()
	if hp.deadline != nil && !hp.deadline.Stop() {
		return context.DeadlineExceeded
	}
	if t.IsZero() {
		return nil
	}
	hp.deadline = time.AfterFunc(time.Until(t), func() {
		hp.mux.Lock()
		defer hp.mux.Unlock()
		if hp.err == nil {
			close(hp.done)
			_ = hp.Close()
		}
	})
	return nil
}

func (hp *hysteria2PacketConn) SetReadDeadline(t time.Time) error {
	return hp.SetDeadline(t)
}

func (hp *hysteria2PacketConn) SetWriteDeadline(t time.Time) error {
	return hp.SetDeadline(t)
}

func normalizeCertHash(hash string) string {
	r := strings.ToLower(hash)
	r = strings.ReplaceAll(r, ":", "")
	r = strings.ReplaceAll(r, "-", "")
	return r
}

// E.g. "100 Mbps", "512 kbps", "1g" are all valid.
func stringToBps(s string) (uint64, error) {
	const (
		_byte    = 1
		kilobyte = _byte * 1000
		megabyte = kilobyte * 1000
		gigabyte = megabyte * 1000
		terabyte = gigabyte * 1000
	)
	if s = strings.ToLower(strings.TrimSpace(s)); s == "" {
		return 0, fmt.Errorf("invalid format: %s", s)
	}
	spl := 0
	for i, c := range s {
		if c < '0' || c > '9' {
			spl = i
			break
		}
	}
	if spl == 0 {
		spl = len(s)
	}
	v, err := strconv.ParseUint(s[:spl], 10, 64)
	if err != nil {
		return 0, err
	}
	unit := strings.TrimSpace(s[spl:])

	switch strings.ToLower(unit) {
	case "b", "bps":
		return v * _byte / 8, nil
	case "k", "kb", "kbps":
		return v * kilobyte / 8, nil
	case "m", "mb", "mbps":
		return v * megabyte / 8, nil
	case "g", "gb", "gbps":
		return v * gigabyte / 8, nil
	case "t", "tb", "tbps":
		return v * terabyte / 8, nil
	case "":
		return v * megabyte / 8, nil
	default:
		return 0, fmt.Errorf("unsupported unit: %s", unit)
	}
}

func convBandwidth(bw any) (uint64, error) {
	switch bwT := bw.(type) {
	case string:
		return stringToBps(bwT)
	case int:
		return uint64(bwT), nil
	default:
		return 0, fmt.Errorf("invalid type %T for bandwidth", bwT)
	}
}
