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

func (t *Table[K, V]) Delete(key K) {
	t.mapping.Delete(key)
}

// New return *Cache
func New[K comparable, V any]() *Table[K, V] {
	return &Table[K, V]{}
}
