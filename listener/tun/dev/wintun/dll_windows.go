/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"fmt"
	"github.com/Dreamacro/clash/listener/tun/dev/wintun/embed_dll"
	"golang.zx2c4.com/wireguard/windows/driver/memmod"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

func newLazyDLL(name string, onLoad func(d *lazyDLL)) *lazyDLL {
	return &lazyDLL{Name: name, onLoad: onLoad}
}

func (d *lazyDLL) NewProc(name string) *lazyProc {
	return &lazyProc{dll: d, Name: name}
}

type lazyProc struct {
	Name string
	mu   sync.Mutex
	dll  *lazyDLL
	addr uintptr
}

func (p *lazyProc) Find() error {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&p.addr))) != nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.addr != 0 {
		return nil
	}

	err := p.dll.Load()
	if err != nil {
		return fmt.Errorf("Error loading %v DLL: %w", p.dll.Name, err)
	}
	addr, err := p.nameToAddr()
	if err != nil {
		return fmt.Errorf("Error getting %v address: %w", p.Name, err)
	}

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&p.addr)), unsafe.Pointer(addr))
	return nil
}

func (p *lazyProc) Addr() uintptr {
	err := p.Find()
	if err != nil {
		panic(err)
	}
	return p.addr
}

type lazyDLL struct {
	Name   string
	mu     sync.Mutex
	module *memmod.Module
	onLoad func(d *lazyDLL)
}

func (d *lazyDLL) Load() error {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&d.module))) != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.module != nil {
		return nil
	}

	module, err := memmod.LoadLibrary(embed_dll.DLLContent)
	if err != nil {
		return fmt.Errorf("Unable to load library: %w", err)
	}

	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&d.module)), unsafe.Pointer(module))
	if d.onLoad != nil {
		d.onLoad(d)
	}
	return nil
}

func (p *lazyProc) nameToAddr() (uintptr, error) {
	return p.dll.module.ProcAddressByName(p.Name)
}

// Version returns the version of the Wintun DLL.
func Version() (version uint32, err error) {
	//if modwintun.Load() != nil {
	//	return "unknown"
	//}
	//resInfo, err := windows.FindResource(modwintun.module, windows.ResourceID(1), windows.RT_VERSION)
	//if err != nil {
	//	return "unknown"
	//}
	//data, err := windows.LoadResourceData(modwintun.module, resInfo)
	//if err != nil {
	//	return "unknown"
	//}
	//
	//var fixedInfo *windows.VS_FIXEDFILEINFO
	//fixedInfoLen := uint32(unsafe.Sizeof(*fixedInfo))
	//err = windows.VerQueryValue(unsafe.Pointer(&data[0]), `\`, unsafe.Pointer(&fixedInfo), &fixedInfoLen)
	//if err != nil {
	//	return "unknown"
	//}
	//version := fmt.Sprintf("%d.%d", (fixedInfo.FileVersionMS>>16)&0xff, (fixedInfo.FileVersionMS>>0)&0xff)
	//if nextNibble := (fixedInfo.FileVersionLS >> 16) & 0xff; nextNibble != 0 {
	//	version += fmt.Sprintf(".%d", nextNibble)
	//}
	//if nextNibble := (fixedInfo.FileVersionLS >> 0) & 0xff; nextNibble != 0 {
	//	version += fmt.Sprintf(".%d", nextNibble)
	//}
	//return version
	r0, _, e1 := syscall.Syscall(procWintunGetRunningDriverVersion.Addr(), 0, 0, 0, 0)
	version = uint32(r0)
	if version == 0 {
		err = e1
	}
	return

}
