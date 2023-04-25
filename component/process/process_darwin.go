package process

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/Dreamacro/clash/common/byteorder"
)

const (
	procpidpathinfo     = 0xb
	procpidpathinfosize = 1024
	proccallnumpidinfo  = 0x2
)

var offset = 408

func init() {
	value, _ := syscall.Sysctl("kern.osrelease")
	before, _, _ := strings.Cut(value, ".")
	n, _ := strconv.ParseInt(before, 10, 64)
	if n < 22 {
		offset = 384
	}
}

func findProcessName(network string, ip netip.Addr, port int) (string, error) {
	var spath string
	switch network {
	case TCP:
		spath = "net.inet.tcp.pcblist_n"
	case UDP:
		spath = "net.inet.udp.pcblist_n"
	default:
		return "", ErrInvalidNetwork
	}

	value, err := syscall.Sysctl(spath)
	if err != nil {
		return "", err
	}

	buf := []byte(value)

	itemSize := offset
	if network == TCP {
		// rup8(sizeof(xtcpcb_n))
		itemSize += 208
	}

	var fallbackUDPProcess string
	// skip the first xinpgen(24 bytes) block
	for i := 24; i+itemSize <= len(buf); i += itemSize {
		// offset of xinpcb_n and xsocket_n
		inp, so := i, i+104

		srcPort := binary.BigEndian.Uint16(buf[inp+18 : inp+20])
		if uint16(port) != srcPort {
			continue
		}

		// xinpcb_n.inp_vflag
		flag := buf[inp+44]

		var srcIP netip.Addr
		switch {
		case flag&0x1 > 0:
			// ipv4
			srcIP, _ = netip.AddrFromSlice(buf[inp+76 : inp+80])
		case flag&0x2 > 0:
			// ipv6
			ipv6 := buf[inp+64 : inp+80]
			ipv6[2] = 0x00
			ipv6[3] = 0x00
			srcIP, _ = netip.AddrFromSlice(ipv6)
		default:
			continue
		}

		if ip.Is4() {
			srcIP = srcIP.Unmap()
		}

		if ip == srcIP {
			// xsocket_n.so_last_pid
			pid := readNativeUint32(buf[so+68 : so+72])
			return getExecPathFromPID(pid)
		}

		// udp packet connection may be not equal with srcIP
		if network == UDP && srcIP.IsUnspecified() && srcIP.Is4() {
			fallbackUDPProcess, _ = getExecPathFromPID(readNativeUint32(buf[so+68 : so+72]))
		}
	}

	if network == UDP && fallbackUDPProcess != "" {
		return fallbackUDPProcess, nil
	}

	return "", ErrNotFound
}

func getExecPathFromPID(pid uint32) (string, error) {
	buf := make([]byte, procpidpathinfosize)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PROC_INFO,
		proccallnumpidinfo,
		uintptr(pid),
		procpidpathinfo,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		procpidpathinfosize)
	if errno != 0 {
		return "", errno
	}

	return unix.ByteSliceToString(buf), nil
}

func readNativeUint32(b []byte) uint32 {
	return byteorder.Native.Uint32(b)
}
