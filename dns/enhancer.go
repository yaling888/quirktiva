package dns

import (
	"net/netip"

	"github.com/yaling888/quirktiva/common/cache"
	"github.com/yaling888/quirktiva/component/fakeip"
	C "github.com/yaling888/quirktiva/constant"
)

type ResolverEnhancer struct {
	mode       C.DNSMode
	fakePool   *fakeip.Pool
	fakePool6  *fakeip.Pool
	mapping    *cache.LruCache[netip.Addr, string]
	cnameCache *cache.LruCache[string, bool]
}

func (h *ResolverEnhancer) FakeIPEnabled() bool {
	return h.mode == C.DNSFakeIP
}

func (h *ResolverEnhancer) MappingEnabled() bool {
	return h.mode != C.DNSNormal
}

func (h *ResolverEnhancer) SniffingEnabled() bool {
	return h.mode == C.DNSSniffing
}

func (h *ResolverEnhancer) IsExistFakeIP(ip netip.Addr) bool {
	if !h.FakeIPEnabled() {
		return false
	}
	pool := h.fakePool
	if ip.Is6() {
		pool = h.fakePool6
	}
	if pool != nil {
		return pool.Exist(ip)
	}

	return false
}

func (h *ResolverEnhancer) IsFakeIP(ip netip.Addr) bool {
	if !h.FakeIPEnabled() {
		return false
	}

	pool := h.fakePool
	if ip.Is6() {
		pool = h.fakePool6
	}
	if pool != nil {
		return pool.IPNet().Contains(ip) && ip != pool.Gateway() && ip != pool.Broadcast()
	}

	return false
}

func (h *ResolverEnhancer) IsFakeBroadcastIP(ip netip.Addr) bool {
	if !h.FakeIPEnabled() {
		return false
	}

	pool := h.fakePool
	if ip.Is6() {
		pool = h.fakePool6
	}
	if pool != nil {
		return pool.Broadcast() == ip
	}

	return false
}

func (h *ResolverEnhancer) FindHostByIP(ip netip.Addr) (string, bool) {
	pool := h.fakePool
	if ip.Is6() {
		pool = h.fakePool6
	}
	if pool != nil {
		if host, existed := pool.LookBack(ip); existed {
			return host, true
		}
	}

	if mapping := h.mapping; mapping != nil {
		if host, existed := mapping.Get(ip); existed {
			return host, true
		}
	}

	return "", false
}

func (h *ResolverEnhancer) FlushFakeIP() (err error) {
	if pool := h.fakePool; pool != nil {
		err = pool.FlushFakeIP()
	}
	if pool := h.fakePool6; pool != nil {
		if err2 := pool.FlushFakeIP(); err2 != nil {
			err = err2
		}
	}
	return
}

func (h *ResolverEnhancer) PatchFrom(o *ResolverEnhancer) {
	if h.mapping != nil && o.mapping != nil {
		o.mapping.CloneTo(h.mapping)
	}

	if h.fakePool != nil && o.fakePool != nil {
		h.fakePool.CloneFrom(o.fakePool)
	}
	if h.fakePool6 != nil && o.fakePool6 != nil {
		h.fakePool6.CloneFrom(o.fakePool6)
	}
}

func (h *ResolverEnhancer) StoreFakePoolState() {
	if h.fakePool != nil {
		h.fakePool.StoreState()
	}
	if h.fakePool6 != nil {
		h.fakePool6.StoreState()
	}
}

func NewEnhancer(cfg Config) *ResolverEnhancer {
	var (
		fakePool   *fakeip.Pool
		fakePool6  *fakeip.Pool
		mapping    *cache.LruCache[netip.Addr, string]
		cnameCache *cache.LruCache[string, bool]
	)

	if cfg.EnhancedMode == C.DNSFakeIP {
		fakePool = cfg.Pool
		fakePool6 = cfg.Pool6
	}
	if cfg.EnhancedMode != C.DNSNormal {
		mapping = cache.New[netip.Addr, string](cache.WithSize[netip.Addr, string](4096))
		cnameCache = cache.New[string, bool](cache.WithSize[string, bool](2048))
	}

	return &ResolverEnhancer{
		mode:       cfg.EnhancedMode,
		fakePool:   fakePool,
		fakePool6:  fakePool6,
		mapping:    mapping,
		cnameCache: cnameCache,
	}
}
