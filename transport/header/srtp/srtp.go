package srtp

import (
	"encoding/binary"
	"math/rand/v2"
)

type SRTP struct {
	header uint16
	number uint16
}

func (*SRTP) Size() int {
	return 4
}

func (s *SRTP) Fill(b []byte) {
	s.number++
	binary.BigEndian.PutUint16(b, s.header)
	binary.BigEndian.PutUint16(b[2:], s.number)
}

func New() *SRTP {
	return &SRTP{
		header: 0xB5E8,
		number: uint16(rand.Uint64() >> 49),
	}
}
