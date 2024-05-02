package dns

import (
	"net/netip"
	"time"

	"github.com/yaling888/clash/common/cache"
	"github.com/yaling888/clash/component/fakeip"
	C "github.com/yaling888/clash/constant"
)

type ResolverEnhancer struct {
	mode     C.DNSMode
	fakePool *fakeip.Pool
	mapping  *cache.LruCache[netip.Addr, string]
}

func (h *ResolverEnhancer) FakeIPEnabled() bool {
	return h.mode == C.DNSFakeIP
}

func (h *ResolverEnhancer) MappingEnabled() bool {
	return h.mode == C.DNSFakeIP || h.mode == C.DNSMapping
}

func (h *ResolverEnhancer) IsExistFakeIP(ip netip.Addr) bool {
	if !h.FakeIPEnabled() {
		return false
	}

	if pool := h.fakePool; pool != nil {
		return pool.Exist(ip)
	}

	return false
}

func (h *ResolverEnhancer) IsFakeIP(ip netip.Addr) bool {
	if !h.FakeIPEnabled() {
		return false
	}

	if pool := h.fakePool; pool != nil {
		return pool.IPNet().Contains(ip) && ip != pool.Gateway() && ip != pool.Broadcast()
	}

	return false
}

func (h *ResolverEnhancer) IsFakeBroadcastIP(ip netip.Addr) bool {
	if !h.FakeIPEnabled() {
		return false
	}

	if pool := h.fakePool; pool != nil {
		return pool.Broadcast() == ip
	}

	return false
}

func (h *ResolverEnhancer) FindHostByIP(ip netip.Addr) (string, bool) {
	if pool := h.fakePool; pool != nil {
		if host, existed := pool.LookBack(ip); existed {
			return host, true
		}
	}

	if host, existed := h.mapping.Get(ip); existed {
		return host, true
	}

	return "", false
}

func (h *ResolverEnhancer) InsertHostByIP(ip netip.Addr, host string) {
	h.mapping.SetWithExpire(ip, host, time.Now().Add(20*time.Minute))
}

func (h *ResolverEnhancer) FlushFakeIP() error {
	if pool := h.fakePool; pool != nil {
		return pool.FlushFakeIP()
	}
	return nil
}

func (h *ResolverEnhancer) PatchFrom(o *ResolverEnhancer) {
	if h.mapping != nil && o.mapping != nil {
		o.mapping.CloneTo(h.mapping)
	}

	if h.fakePool != nil && o.fakePool != nil {
		h.fakePool.CloneFrom(o.fakePool)
	}
}

func (h *ResolverEnhancer) StoreFakePoolState() {
	if h.fakePool != nil {
		h.fakePool.StoreState()
	}
}

func NewEnhancer(cfg Config) *ResolverEnhancer {
	return &ResolverEnhancer{
		mode:     cfg.EnhancedMode,
		fakePool: cfg.Pool,
		mapping:  cache.New[netip.Addr, string](cache.WithSize[netip.Addr, string](8192)),
	}
}
