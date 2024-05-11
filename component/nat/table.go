package nat

import (
	"sync"
)

type Table[K comparable, V any] struct {
	mapping sync.Map
}

func (t *Table[K, V]) Set(key K, value V) {
	t.mapping.Store(key, value)
}

func (t *Table[K, V]) Get(key K) V {
	item, exist := t.mapping.Load(key)
	if !exist {
		var v V
		return v
	}
	return item.(V)
}

func (t *Table[K, V]) GetOrCreateLock(key K) (*sync.Cond, bool) {
	item, loaded := t.mapping.LoadOrStore(key, sync.NewCond(&sync.Mutex{}))
	return item.(*sync.Cond), loaded
}

func (t *Table[K, V]) Load(key K) (value V, ok bool) {
	item, exist := t.mapping.Load(key)
	if !exist {
		var v V
		return v, false
	}
	value, ok = item.(V)
	return
}

func (t *Table[K, V]) LoadOrStore(key K, newValue V) (actual V, loaded bool) {
	item, loaded := t.mapping.LoadOrStore(key, newValue)
	return item.(V), loaded
}

func (t *Table[K, V]) Delete(key K) {
	t.mapping.Delete(key)
}

// Range calls f sequentially for each key and value present in the map.
// If f returns false, range stops the iteration.
func (t *Table[K, V]) Range(f func(key K, value V) bool) {
	t.mapping.Range(func(key, value any) bool {
		return f(key.(K), value.(V))
	})
}

// New return *Cache
func New[K comparable, V any]() *Table[K, V] {
	return &Table[K, V]{}
}
