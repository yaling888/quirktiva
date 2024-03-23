package wireguard

type Wireguard struct{}

func (*Wireguard) Size() int {
	return 4
}

func (*Wireguard) Fill(b []byte) {
	b[0] = 0x04
	b[1] = 0x00
	b[2] = 0x00
	b[3] = 0x00
}

func New() *Wireguard {
	return &Wireguard{}
}
