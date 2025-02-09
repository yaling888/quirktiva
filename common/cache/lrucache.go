package cache

// Modified by https://github.com/die-net/lrucache

import (
	"sync"
	"time"
	"weak"

	"github.com/yaling888/quirktiva/common/generics/list"
)

// Option is part of Functional Options Pattern
type Option[K comparable, V any] func(*LruCache[K, V])

// EvictCallback is used to get a callback when a cache entry is evicted
type EvictCallback[K comparable, V any] func(key K, value V)

// WithEvict set to evict callback
func WithEvict[K comparable, V any](cb EvictCallback[K, V]) Option[K, V] {
	return func(l *LruCache[K, V]) {
		l.onEvict = cb
	}
}

// WithUpdateAgeOnGet update expires when Get element
func WithUpdateAgeOnGet[K comparable, V any]() Option[K, V] {
	return func(l *LruCache[K, V]) {
		l.updateAgeOnGet = true
	}
}

// WithAge defined element max age (second)
func WithAge[K comparable, V any](maxAge int64) Option[K, V] {
	return func(l *LruCache[K, V]) {
		l.maxAge = maxAge
	}
}

// WithSize defined max length of LruCache
func WithSize[K comparable, V any](maxSize int) Option[K, V] {
	return func(l *LruCache[K, V]) {
		l.maxSize = maxSize
	}
}

// WithStale decide whether Stale return is enabled.
// If this feature is enabled, element will not get Evicted according to `WithAge`.
func WithStale[K comparable, V any](stale bool) Option[K, V] {
	return func(l *LruCache[K, V]) {
		l.staleReturn = stale
	}
}

// LruCache is a thread-safe, in-memory lru-cache that evicts the
// least recently used entries from memory when (if set) the entries are
// older than maxAge (in seconds).  Use the New constructor to create one.
type LruCache[K comparable, V any] struct {
	maxAge         int64
	maxSize        int
	mu             sync.Mutex
	cache          map[K]weak.Pointer[list.Element[*entry[K, V]]]
	lru            *list.List[*entry[K, V]] // Front is least-recent
	updateAgeOnGet bool
	staleReturn    bool
	onEvict        EvictCallback[K, V]
}

// New creates an LruCache
func New[K comparable, V any](options ...Option[K, V]) *LruCache[K, V] {
	lc := &LruCache[K, V]{
		lru:   list.New[*entry[K, V]](),
		cache: make(map[K]weak.Pointer[list.Element[*entry[K, V]]]),
	}

	for _, option := range options {
		option(lc)
	}

	return lc
}

// Get returns any representation of a cached response and a bool
// set to true if the key was found.
func (c *LruCache[K, V]) Get(key K) (V, bool) {
	el := c.get(key)
	if el == nil {
		return empty[V](), false
	}
	value := el.value

	return value, true
}

// GetWithExpire returns any representation of a cached response,
// a time.Time Give expected expires,
// and a bool set to true if the key was found.
// This method will NOT check the maxAge of element and will NOT update the expires.
func (c *LruCache[K, V]) GetWithExpire(key K) (V, time.Time, bool) {
	el := c.get(key)
	if el == nil {
		return empty[V](), time.Time{}, false
	}

	return el.value, time.Unix(el.expires, 0), true
}

// Exist returns if key exist in cache but not put item to the head of linked list
func (c *LruCache[K, V]) Exist(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.cache[key]
	return ok
}

// Set stores any representation of a response for a given key.
func (c *LruCache[K, V]) Set(key K, value V) {
	expires := int64(0)
	if c.maxAge > 0 {
		expires = time.Now().Unix() + c.maxAge
	}
	c.SetWithExpire(key, value, time.Unix(expires, 0))
}

// SetWithExpire stores any representation of a response for a given key and given expires.
// The expires time will round to second.
func (c *LruCache[K, V]) SetWithExpire(key K, value V, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if le, ok := c.cache[key]; ok {
		if ev := le.Value(); ev != nil {
			ev.Value = &entry[K, V]{key: key, value: value, expires: expires.Unix()}
			c.lru.MoveToBack(ev)
			ew := weak.Make(ev)
			c.cache[key] = ew
			c.maybeDeleteOldest()
			return
		} else {
			c.deleteElement(key)
		}
	}

	el := c.lru.PushBack(&entry[K, V]{key: key, value: value, expires: expires.Unix()})
	ew := weak.Make(el)
	c.cache[key] = ew

	if c.maxSize > 0 {
		if elLen := c.lru.Len(); elLen > c.maxSize {
			c.deleteElement(c.lru.Front().Value.key)
		}
	}

	c.maybeDeleteOldest()
}

// CloneTo clone and overwrite elements to another LruCache
func (c *LruCache[K, V]) CloneTo(n *LruCache[K, V]) {
	c.mu.Lock()
	defer c.mu.Unlock()

	n.mu.Lock()
	defer n.mu.Unlock()

	n.lru.Init()
	clear(n.cache)

	for e := c.lru.Front(); e != nil; e = e.Next() {
		elm := e.Value
		le := n.lru.PushBack(elm)
		ew := weak.Make(le)
		n.cache[elm.key] = ew
	}
}

func (c *LruCache[K, V]) get(key K) *entry[K, V] {
	c.mu.Lock()
	defer c.mu.Unlock()

	le, ok := c.cache[key]
	if !ok {
		return nil
	}

	ev := le.Value()
	if ev == nil {
		c.deleteElement(key)
		return nil
	}

	if !c.staleReturn && c.maxAge > 0 && ev.Value.expires <= time.Now().Unix() {
		c.deleteElement(ev.Value.key)
		c.maybeDeleteOldest()

		return nil
	}

	c.lru.MoveToBack(ev)
	el := ev.Value
	if c.maxAge > 0 && c.updateAgeOnGet {
		el.expires = time.Now().Unix() + c.maxAge
	}
	return el
}

// Delete removes the value associated with a key.
func (c *LruCache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.deleteElement(key)
}

func (c *LruCache[K, V]) maybeDeleteOldest() {
	if !c.staleReturn && c.maxAge > 0 {
		now := time.Now().Unix()
		for le := c.lru.Front(); le != nil && le.Value.expires <= now; le = c.lru.Front() {
			c.deleteElement(le.Value.key)
		}
	}
}

func (c *LruCache[K, V]) deleteElement(key K) {
	if elem, exists := c.cache[key]; exists {
		if ev := elem.Value(); ev != nil {
			c.lru.Remove(ev)
			if c.onEvict != nil {
				e := ev.Value
				c.onEvict(e.key, e.value)
			}
		}
		delete(c.cache, key)
	}
}

func (c *LruCache[K, V]) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lru.Init()
	clear(c.cache)
	return nil
}

func empty[T any]() T {
	var zero T
	return zero
}

type entry[K comparable, V any] struct {
	key     K
	value   V
	expires int64
}
