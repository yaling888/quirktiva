package rand

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
)

const (
	rngMax  = 1 << 63
	rngMask = rngMax - 1
)

var Reader = rand.Reader

// Intn returns a uniform random value in [0, max). It panics if max <= 0.
func Intn(max int) int {
	b, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(b.Int64())
}

// IntnRange generates an integer in range [min, max).
// By design this should panic if input is invalid, <= 0.
func IntnRange(min, max int) int {
	return Intn(max-min) + min
}

func Int() int {
	u := uint(Int63())
	return int(u << 1 >> 1)
}

func Int31() int32 {
	return int32(Int63() >> 32)
}

func Int63() int64 {
	return int64(Uint64() & rngMask)
}

func Uint32() uint32 {
	return uint32(Int63() >> 31)
}

func Uint64() uint64 {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0
	}
	return binary.NativeEndian.Uint64(b)
}

func Float32() float32 {
again:
	f := float32(Float64())
	if f == 1 {
		goto again
	}
	return f
}

func Float64() float64 {
again:
	f := float64(Int63()) / rngMax
	if f == 1 {
		goto again
	}
	return f
}

func Read(b []byte) (n int, err error) {
	return rand.Read(b)
}
