package wechat

import (
	"encoding/binary"
	"math/rand/v2"
)

type VideoChat struct {
	sn uint32
}

func (vc *VideoChat) Size() int {
	return 13
}

func (vc *VideoChat) Fill(b []byte) {
	vc.sn++
	b[0] = 0xa1
	b[1] = 0x08
	binary.BigEndian.PutUint32(b[2:], vc.sn)
	b[6] = 0x00
	b[7] = 0x10
	b[8] = 0x11
	b[9] = 0x18
	b[10] = 0x30
	b[11] = 0x22
	b[12] = 0x30
}

func New() *VideoChat {
	return &VideoChat{
		sn: uint32(rand.Uint64() >> 40),
	}
}
