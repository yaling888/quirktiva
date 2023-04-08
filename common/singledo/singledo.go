package singledo

import (
	"sync"
	"time"
)

type call[T any] struct {
	wg  sync.WaitGroup
	val T
	err error
}

type Single[T any] struct {
	mux    sync.Mutex
	last   time.Time
	wait   time.Duration
	call   *call[T]
	result *Result[T]
}

type Result[T any] struct {
	Val T
	Err error
}

// Do single.Do likes sync.singleFlight
func (s *Single[T]) Do(fn func() (T, error)) (v T, err error, shared bool) {
	s.mux.Lock()
	now := time.Now()
	if now.Before(s.last.Add(s.wait)) {
		s.mux.Unlock()
		return s.result.Val, s.result.Err, true
	}

	if callM := s.call; callM != nil {
		s.mux.Unlock()
		callM.wg.Wait()
		return callM.val, callM.err, true
	}

	callM := &call[T]{}
	callM.wg.Add(1)
	s.call = callM
	s.mux.Unlock()
	callM.val, callM.err = fn()
	callM.wg.Done()

	s.mux.Lock()
	s.call = nil
	s.result = &Result[T]{callM.val, callM.err}
	s.last = now
	s.mux.Unlock()
	return callM.val, callM.err, false
}

func (s *Single[T]) Reset() {
	s.last = time.Time{}
}

func NewSingle[T any](wait time.Duration) *Single[T] {
	return &Single[T]{wait: wait}
}

type Group[T any] struct {
	mu sync.Mutex          // protects m
	m  map[string]*call[T] // lazily initialized
}

func (g *Group[T]) Do(key string, fn func() (T, error)) (v T, err error, shared bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*call[T])
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()

		return c.val, c.err, true
	}
	c := new(call[T])
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()
	c.val, c.err = fn()
	c.wg.Done()

	return c.val, c.err, false
}

func (g *Group[T]) Forget(key string) {
	g.mu.Lock()
	if g.m == nil {
		g.mu.Unlock()
		return
	}
	if c, ok := g.m[key]; ok {
		var v T
		c.val = v
	}
	delete(g.m, key)
	g.mu.Unlock()
}
