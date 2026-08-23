package nat

import (
	"sync"
	"sync/atomic"
)

type Lock struct {
	ref  atomic.Int64
	mux  sync.Mutex
	once sync.Once
	done chan struct{}
	fn   func()
}

func (s *Lock) Lock() {
	s.ref.Add(1)
	s.mux.Lock()
}

func (s *Lock) Unlock() {
	r := s.ref.Add(-1)
	s.mux.Unlock()
	if f := s.fn; f != nil && r == 0 {
		s.fn = nil
		f()
	}
}

func (s *Lock) Wait() {
	<-s.done
}

func (s *Lock) Done() {
	s.once.Do(func() { close(s.done) })
}

func (s *Lock) C() <-chan struct{} {
	return s.done
}

func (s *Lock) TryRelease() bool {
	if f := s.fn; f != nil && s.ref.Load() == 0 {
		s.fn = nil
		f()
		return true
	}
	return false
}

func NewLocker(releaseFn func()) *Lock {
	return &Lock{
		done: make(chan struct{}),
		fn:   releaseFn,
	}
}
