package pool

import "sync"

const (
	NetBufferSize = 64 << 10
)

var netBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, NetBufferSize)
		return &b
	},
}

func GetNetBuf() *[]byte {
	return netBufferPool.Get().(*[]byte)
}

func PutNetBuf(bufP *[]byte) {
	if bufP == nil {
		panic("bufP is nil")
	}
	if cap(*bufP) < NetBufferSize {
		panic("invalid bufP capacity")
	}
	if len(*bufP) < NetBufferSize {
		*bufP = (*bufP)[:NetBufferSize]
	}
	netBufferPool.Put(bufP)
}
