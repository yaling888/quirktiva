package tun

import (
	"fmt"

	"github.com/yaling888/clash/listener/tun/device"
)

func Open(name string, mtu uint32) (_ device.Device, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("open tun: %v", r)
		}
	}()

	t := &TUN{
		name:   name,
		mtu:    mtu,
		offset: offset,
	}

	forcedMTU := defaultMTU
	if t.mtu > 0 {
		forcedMTU = int(t.mtu)
	}

	nt, err := newDevice(t.name, forcedMTU)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}

	t.nt = nt

	tunMTU, err := nt.MTU()
	if err != nil {
		return nil, fmt.Errorf("get mtu: %w", err)
	}

	if tunMTU > 0 {
		t.mtu = uint32(tunMTU)
	}

	return t, nil
}

func (t *TUN) Read(buffs [][]byte, sizes []int, offset int) (n int, err error) {
	return t.nt.Read(buffs, sizes, offset)
}

func (t *TUN) Write(buffs [][]byte, offset int) (int, error) {
	return t.nt.Write(buffs, offset)
}

func (t *TUN) Name() string {
	name, _ := t.nt.Name()
	return name
}

func (t *TUN) MTU() uint32 {
	mtu, err := t.nt.MTU()
	if err != nil {
		return t.mtu
	}
	return uint32(mtu)
}

func (t *TUN) BatchSize() int {
	return t.nt.BatchSize()
}

func (t *TUN) Offset() int {
	return t.offset
}

func (t *TUN) UseIOBased() error {
	return nil
}
