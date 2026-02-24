package observable

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"
)

func iterator[T any](item []T) chan T {
	ch := make(chan T)
	go func() {
		time.Sleep(100 * time.Millisecond)
		for _, elm := range item {
			ch <- elm
		}
		close(ch)
	}()
	return ch
}

func TestObservable(t *testing.T) {
	iter := iterator[int]([]int{1, 2, 3, 4, 5})
	src := NewObservable[int](iter)
	data, err := src.Subscribe()
	assert.Nil(t, err)
	count := 0
	for range data {
		count++
	}
	assert.Equal(t, count, 5)
}

func TestObservable_MultiSubscribe(t *testing.T) {
	iter := iterator[int]([]int{1, 2, 3, 4, 5})
	src := NewObservable[int](iter)
	ch1, _ := src.Subscribe()
	ch2, _ := src.Subscribe()
	count := atomic.NewInt32(0)

	var wg sync.WaitGroup
	waitCh := func(ch <-chan int) {
		for range ch {
			count.Inc()
		}
	}
	wg.Go(func() { waitCh(ch1) })
	wg.Go(func() { waitCh(ch2) })
	wg.Wait()
	assert.Equal(t, int32(10), count.Load())
}

func TestObservable_UnSubscribe(t *testing.T) {
	iter := iterator[int]([]int{1, 2, 3, 4, 5})
	src := NewObservable[int](iter)
	data, err := src.Subscribe()
	assert.Nil(t, err)
	src.UnSubscribe(data)
	_, open := <-data
	assert.False(t, open)
}

func TestObservable_SubscribeClosedSource(t *testing.T) {
	iter := iterator[int]([]int{1})
	src := NewObservable[int](iter)
	data, _ := src.Subscribe()
	<-data

	_, closed := src.Subscribe()
	assert.NotNil(t, closed)
}

func TestObservable_UnSubscribeWithNotExistSubscription(t *testing.T) {
	sub := Subscription[int](make(chan int))
	iter := iterator[int]([]int{1})
	src := NewObservable[int](iter)
	src.UnSubscribe(sub)
}

func TestObservable_SubscribeGoroutineLeak(t *testing.T) {
	iter := iterator[int]([]int{1, 2, 3, 4, 5})
	src := NewObservable[int](iter)
	total := 100

	var list []Subscription[int]
	for i := 0; i < total; i++ {
		ch, _ := src.Subscribe()
		list = append(list, ch)
	}

	var wg sync.WaitGroup
	waitCh := func(ch <-chan int) {
		for range ch {
		}
	}

	for _, ch := range list {
		wg.Go(func() { waitCh(ch) })
	}
	wg.Wait()

	for _, sub := range list {
		_, more := <-sub
		assert.False(t, more)
	}

	_, more := <-list[0]
	assert.False(t, more)
}

func Benchmark_Observable_1000(b *testing.B) {
	ch := make(chan int)
	o := NewObservable[int](ch)
	num := 1000

	subs := []Subscription[int]{}
	for i := 0; i < num; i++ {
		sub, _ := o.Subscribe()
		subs = append(subs, sub)
	}

	wg := sync.WaitGroup{}

	b.ResetTimer()
	for _, sub := range subs {
		wg.Go(func() {
			func(s Subscription[int]) {
				for range s {
				}
			}(sub)
		})
	}

	for i := 0; i < b.N; i++ {
		ch <- i
	}

	close(ch)
	wg.Wait()
}
