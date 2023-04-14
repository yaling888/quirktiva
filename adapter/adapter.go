package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"time"

	"go.uber.org/atomic"

	"github.com/Dreamacro/clash/common/queue"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
)

type Proxy struct {
	C.ProxyAdapter
	history *queue.Queue[C.DelayHistory]
	alive   *atomic.Bool
	hasV6   *atomic.Bool
	v6Mux   sync.Mutex
}

// Alive implements C.Proxy
func (p *Proxy) Alive() bool {
	return p.alive.Load()
}

// HasV6 implements C.Proxy
func (p *Proxy) HasV6() bool {
	if p.hasV6 == nil {
		return false
	}
	return p.hasV6.Load()
}

// Dial implements C.Proxy
func (p *Proxy) Dial(metadata *C.Metadata) (C.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	return p.DialContext(ctx, metadata)
}

// DialContext implements C.ProxyAdapter
func (p *Proxy) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	conn, err := p.ProxyAdapter.DialContext(ctx, metadata, opts...)
	if !errors.Is(context.Canceled, err) {
		p.alive.Store(err == nil)
	}
	return conn, err
}

// DialUDP implements C.ProxyAdapter
func (p *Proxy) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
	defer cancel()
	return p.ListenPacketContext(ctx, metadata)
}

// ListenPacketContext implements C.ProxyAdapter
func (p *Proxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	pc, err := p.ProxyAdapter.ListenPacketContext(ctx, metadata, opts...)
	if !errors.Is(context.Canceled, err) {
		p.alive.Store(err == nil)
	}
	return pc, err
}

// DelayHistory implements C.Proxy
func (p *Proxy) DelayHistory() []C.DelayHistory {
	queueM := p.history.Copy()
	histories := []C.DelayHistory{}
	histories = append(histories, queueM...)
	return histories
}

// LastDelay return last history record. if proxy is not alive, return the max value of uint16.
// implements C.Proxy
func (p *Proxy) LastDelay() (delay uint16) {
	var max uint16 = 0xffff
	if !p.alive.Load() {
		return max
	}

	history := p.history.Last()
	if history.Delay == 0 {
		return max
	}
	return history.Delay
}

// MarshalJSON implements C.ProxyAdapter
func (p *Proxy) MarshalJSON() ([]byte, error) {
	inner, err := p.ProxyAdapter.MarshalJSON()
	if err != nil {
		return inner, err
	}

	mapping := map[string]any{}
	_ = json.Unmarshal(inner, &mapping)
	mapping["history"] = p.DelayHistory()
	mapping["name"] = p.Name()
	mapping["udp"] = p.SupportUDP()
	return json.Marshal(mapping)
}

// URLTest get the delay for the specified URL
// implements C.Proxy
func (p *Proxy) URLTest(ctx context.Context, url string) (delay, avgDelay uint16, err error) {
	defer func() {
		alive := err == nil
		p.alive.Store(alive)
		record := C.DelayHistory{Time: time.Now()}
		if alive {
			record.Delay = delay
			record.AvgDelay = avgDelay
			if p.hasV6 == nil && resolver.RemoteDnsResolve && !p.ProxyAdapter.DisableDnsResolve() {
				go p.v6Test(url)
			}
		}
		p.history.Put(record)
		if p.history.Len() > 10 {
			p.history.Pop()
		}
	}()

	addr, err := urlToMetadata(url)
	if err != nil {
		return
	}

	start := time.Now()
	instance, err := p.DialContext(ctx, &addr)
	if err != nil {
		return
	}
	defer func() {
		_ = instance.Close()
	}()

	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return
	}
	req = req.WithContext(ctx)

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return instance, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
	delay = uint16(time.Since(start) / time.Millisecond)

	resp, err = client.Do(req)
	if err != nil {
		avgDelay = 0
		err = nil
		return
	}
	_ = resp.Body.Close()
	avgDelay = uint16(time.Since(start) / time.Millisecond / 2)

	return
}

func (p *Proxy) v6Test(url string) {
	p.v6Mux.Lock()
	if p.hasV6 != nil {
		return
	}

	var (
		resolved bool
		err      error
	)

	defer func() {
		if resolved {
			p.hasV6 = atomic.NewBool(err == nil)
		}
		p.v6Mux.Unlock()
	}()

	addr, err := urlToMetadata(url)
	if err != nil {
		return
	}

	ips, err := resolver.LookupIPv6ByProxy(context.Background(), addr.Host, p.Name())
	if err != nil {
		if os.IsTimeout(err) || errors.Is(err, resolver.ErrIPNotFound) || errors.Is(err, resolver.ErrIPVersion) {
			resolved = true
		}
		return
	}
	addr.DstIP = ips[0]
	resolved = true

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	instance, err := p.DialContext(ctx, &addr)
	if err != nil {
		return
	}
	defer func() {
		_ = instance.Close()
	}()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req = req.WithContext(ctx)

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return instance, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func NewProxy(adapter C.ProxyAdapter) *Proxy {
	return &Proxy{
		ProxyAdapter: adapter,
		history:      queue.New[C.DelayHistory](10),
		alive:        atomic.NewBool(true),
	}
}

func urlToMetadata(rawURL string) (addr C.Metadata, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			err = fmt.Errorf("%s scheme not Support", rawURL)
			return
		}
	}

	addr = C.Metadata{
		Host:    u.Hostname(),
		DstIP:   netip.Addr{},
		DstPort: port,
	}
	return
}
