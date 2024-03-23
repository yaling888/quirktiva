package utp

import (
	"encoding/binary"
	"math/rand/v2"
)

type UTP struct {
	header       byte
	extension    byte
	connectionID uint16
}

func (*UTP) Size() int {
	return 4
}

func (u *UTP) Fill(b []byte) {
	binary.BigEndian.PutUint16(b, u.connectionID)
	b[2] = u.header
	b[3] = u.extension
}

func New() *UTP {
	return &UTP{
		header:       1,
		extension:    0,
		connectionID: uint16(rand.Uint64() >> 49),
	}
}
