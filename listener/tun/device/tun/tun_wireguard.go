package tun

import (
	"fmt"
	"os"
	"runtime"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/device/iobased"
)

type TUN struct {
	*iobased.Endpoint

	nt     tun.Device
	mtu    uint32
	name   string
	offset int
}

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

	nt, err := newDevice(t.name, forcedMTU) // forcedMTU do not work on wintun, need to be setting by other way

	// retry if abnormal exit at last time on Windows
	if err != nil && runtime.GOOS == "windows" && os.IsExist(err) {
		nt, err = newDevice(t.name, forcedMTU)
	}

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

func (t *TUN) Close() error {
	t.close()

	defer func(ep *iobased.Endpoint) {
		if ep != nil {
			ep.Close()
		}
	}(t.Endpoint)
	return t.nt.Close()
}

func (t *TUN) Name() string {
	name, _ := t.nt.Name()
	return name
}

func (t *TUN) MTU() uint32 {
	return t.mtu
}

func (t *TUN) BatchSize() int {
	return t.nt.BatchSize()
}

func (t *TUN) Offset() int {
	return t.offset
}

func (t *TUN) UseEndpoint() error {
	ep, err := iobased.New(t, t.mtu, t.offset)
	if err != nil {
		return fmt.Errorf("create endpoint: %w", err)
	}
	t.Endpoint = ep
	return nil
}

func (t *TUN) UseIOBased() error {
	return nil
}
