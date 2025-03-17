package ebpf

import (
	"net/netip"

	C "github.com/yaling888/quirktiva/constant"
)

type TcEBpfProgram struct {
	pros    []C.EBpf
	rawNICs []string
}

func (t *TcEBpfProgram) RawNICs() []string {
	return t.rawNICs
}

func (t *TcEBpfProgram) Close() {
	for _, p := range t.pros {
		p.Close()
	}
}

func (t *TcEBpfProgram) Lookup(srcAddrPort netip.AddrPort) (addr netip.AddrPort, err error) {
	for _, p := range t.pros {
		addr, err = p.Lookup(srcAddrPort)
		if err == nil {
			return
		}
	}
	return
}

func (t *TcEBpfProgram) LookupUDP(srcAddrPort netip.AddrPort) (addr netip.AddrPort, err error) {
	for _, p := range t.pros {
		addr, err = p.LookupUDP(srcAddrPort)
		if err == nil {
			return
		}
	}
	return
}

func NewAutoRedirProgram(pros []C.EBpf, rawNICs []string) *TcEBpfProgram {
	return &TcEBpfProgram{
		pros:    pros,
		rawNICs: rawNICs,
	}
}
