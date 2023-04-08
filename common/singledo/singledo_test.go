package singledo

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"
)

func TestBasic(t *testing.T) {
	single := NewSingle[int](time.Millisecond * 30)
	foo := 0
	shardCount := atomic.NewInt32(0)
	call := func() (int, error) {
		foo++
		time.Sleep(time.Millisecond * 5)
		return 0, nil
	}

	var wg sync.WaitGroup
	const n = 5
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			_, _, shard := single.Do(call)
			if shard {
				shardCount.Inc()
			}
			wg.Done()
		}()
	}

	wg.Wait()
	assert.Equal(t, 1, foo)
	assert.Equal(t, int32(4), shardCount.Load())
}

func TestTimer(t *testing.T) {
	single := NewSingle[int](time.Millisecond * 30)
	foo := 0
	callM := func() (int, error) {
		foo++
		return 0, nil
	}

	_, _, _ = single.Do(callM)
	time.Sleep(10 * time.Millisecond)
	_, _, shard := single.Do(callM)

	assert.Equal(t, 1, foo)
	assert.True(t, shard)
}

func TestReset(t *testing.T) {
	single := NewSingle[int](time.Millisecond * 30)
	foo := 0
	callM := func() (int, error) {
		foo++
		return 0, nil
	}

	_, _, _ = single.Do(callM)
	single.Reset()
	_, _, _ = single.Do(callM)

	assert.Equal(t, 2, foo)
}

func TestGroup_Do(t *testing.T) {
	g := &Group[string]{}
	key := "1"
	type args struct {
		key string
		fn  func() (string, error)
	}
	tests := []struct {
		name       string
		args       args
		wantV      string
		wantErr    error
		wantShared bool
	}{
		{
			name: "1",
			args: args{
				key: key,
				fn: func() (string, error) {
					time.Sleep(time.Millisecond * 30)
					return "1", nil
				},
			},
			wantV:      "1",
			wantErr:    nil,
			wantShared: false,
		},
		{
			name: "2",
			args: args{
				key: key,
				fn: func() (string, error) {
					return "2", nil
				},
			},
			wantV:      "1",
			wantErr:    nil,
			wantShared: true,
		},
		{
			name: "3",
			args: args{
				key: key,
				fn: func() (string, error) {
					time.Sleep(time.Millisecond * 30)
					return "3", nil
				},
			},
			wantV:      "3",
			wantErr:    nil,
			wantShared: false,
		},
		{
			name: "4",
			args: args{
				key: key,
				fn: func() (string, error) {
					return "4", nil
				},
			},
			wantV:      "3",
			wantErr:    nil,
			wantShared: true,
		},
		{
			name: "5",
			args: args{
				key: key,
				fn: func() (string, error) {
					return "5", nil
				},
			},
			wantV:      "3",
			wantErr:    nil,
			wantShared: true,
		},
	}

	for _, tt := range tests {
		if tt.name == "3" {
			g.Forget(key)
		}

		t.Run(tt.name, func(t *testing.T) {
			gotV, gotErr, gotShared := g.Do(tt.args.key, tt.args.fn)
			assert.Equalf(t, tt.wantV, gotV, "Do(%v, %v)", tt.args.key, tt.args.fn)
			assert.Equalf(t, tt.wantErr, gotErr, "Do(%v, %v)", tt.args.key, tt.args.fn)
			assert.Equalf(t, tt.wantShared, gotShared, "Do(%v, %v)", tt.args.key, tt.args.fn)
		})
	}
}
