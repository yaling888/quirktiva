package redir

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/Dreamacro/clash/transport/socks5"
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

	var addr netip.AddrPort

	rc.Control(func(fd uintptr) {
		if ip4 := c.LocalAddr().(*net.TCPAddr).IP.To4(); ip4 != nil {
			addr, err = getorigdst(fd)
		} else {
			addr, err = getorigdst6(fd)
		}
	})

	return socks5.AddrFromStdAddrPort(addr), err
}

// Call getorigdst() from linux/net/ipv4/netfilter/nf_conntrack_l3proto_ipv4.c
func getorigdst(fd uintptr) (netip.AddrPort, error) {
	addr4 := unix.RawSockaddrInet4{}
	size := uint32(unsafe.Sizeof(addr4))
	if err := socketcall(GETSOCKOPT, fd, unix.IPPROTO_IP, unix.SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&addr4)), uintptr(unsafe.Pointer(&size)), 0); err != nil {
		return netip.AddrPort{}, err
	}
	port := binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&addr4.Port)))[:])
	return netip.AddrPortFrom(netip.AddrFrom4(addr4.Addr), port), nil
}

func getorigdst6(fd uintptr) (netip.AddrPort, error) {
	addr6 := unix.RawSockaddrInet6{}
	size := uint32(unsafe.Sizeof(addr6))
	if err := socketcall(GETSOCKOPT, fd, unix.IPPROTO_IPV6, unix.SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&addr6)), uintptr(unsafe.Pointer(&size)), 0); err != nil {
		return netip.AddrPort{}, err
	}
	port := binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&addr6.Port)))[:])
	return netip.AddrPortFrom(netip.AddrFrom16(addr6.Addr), port), nil
}
