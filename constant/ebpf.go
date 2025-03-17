package constant

import (
	"net/netip"
)

const (
	BpfFSPath = "/sys/fs/bpf/clash"

	TcpAutoRedirPort = 't'<<8 | 'r'<<0
	ClashTrafficMark = 'c'<<24 | 'l'<<16 | 't'<<8 | 'm'<<0
)

type EBpf interface {
	Start() error
	Close()
	Lookup(srcAddrPort netip.AddrPort) (netip.AddrPort, error)
	LookupUDP(srcAddrPort netip.AddrPort) (netip.AddrPort, error)
}
