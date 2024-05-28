package redir

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/yaling888/quirktiva/transport/socks5"
)

const (
	SO_ORIGINAL_DST      = 80 // from linux/include/uapi/linux/netfilter_ipv4.h
	IP6T_SO_ORIGINAL_DST = 80 // from linux/include/uapi/linux/netfilter_ipv6/ip6_tables.h
)

func parserPacket(conn net.Conn) (socks5.Addr, error) {
	c, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, errors.New("only work with TCP connection")
	}

	rc, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}

	var (
		addr     netip.AddrPort
		innerErr error
	)

	err = rc.Control(func(fd uintptr) {
		if ip4 := c.LocalAddr().(*net.TCPAddr).IP.To4(); ip4 != nil {
			addr, innerErr = getorigdst(fd)
		} else {
			addr, innerErr = getorigdst6(fd)
		}
	})

	if innerErr != nil {
		err = innerErr
	}

	return socks5.AddrFromStdAddrPort(addr), err
}

// Call getorigdst() from linux/net/ipv4/netfilter/nf_conntrack_l3proto_ipv4.c
func getorigdst(fd uintptr) (netip.AddrPort, error) {
	addr := unix.RawSockaddrInet4{}
	size := uint32(unsafe.Sizeof(addr))
	_, _, err := syscall.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_IP, SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0)
	if err != 0 {
		return netip.AddrPort{}, err
	}
	port := binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&addr.Port)))[:])
	return netip.AddrPortFrom(netip.AddrFrom4(addr.Addr), port), nil
}

func getorigdst6(fd uintptr) (netip.AddrPort, error) {
	addr := unix.RawSockaddrInet6{}
	size := uint32(unsafe.Sizeof(addr))
	_, _, err := syscall.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0)
	if err != 0 {
		return netip.AddrPort{}, err
	}
	port := binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&addr.Port)))[:])
	return netip.AddrPortFrom(netip.AddrFrom16(addr.Addr), port), nil
}
