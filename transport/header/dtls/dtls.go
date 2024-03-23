package dtls

import (
	"math/rand/v2"
)

type DTLS struct {
	epoch    uint16
	length   uint16
	sequence uint32
}

func (*DTLS) Size() int {
	return 13
}

func (d *DTLS) Fill(b []byte) {
	b[0] = 23
	b[1] = 254
	b[2] = 253
	b[3] = byte(d.epoch >> 8)
	b[4] = byte(d.epoch)
	b[5] = 0
	b[6] = 0
	b[7] = byte(d.sequence >> 24)
	b[8] = byte(d.sequence >> 16)
	b[9] = byte(d.sequence >> 8)
	b[10] = byte(d.sequence)
	d.sequence++
	b[11] = byte(d.length >> 8)
	b[12] = byte(d.length)
	d.length += 17
	if d.length > 100 {
		d.length -= 50
	}
}

func New() *DTLS {
	return &DTLS{
		epoch:    uint16(rand.Uint64() >> 49),
		sequence: 0,
		length:   17,
	}
}
