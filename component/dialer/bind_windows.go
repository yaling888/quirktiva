package dialer

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/Dreamacro/clash/component/ebpf/byteorder"
	"github.com/Dreamacro/clash/component/iface"
)

const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

type controlFn = func(network, address string, c syscall.RawConn) error

func bindControl(ifaceIdx int, chain controlFn) controlFn {
	return func(network, address string, c syscall.RawConn) (err error) {
		defer func() {
			if err == nil && chain != nil {
				err = chain(network, address, c)
			}
		}()

		addrPort, err := netip.ParseAddrPort(address)
		if err == nil && !addrPort.Addr().IsGlobalUnicast() {
			return
		}

		var innerErr error
		err = c.Control(func(fd uintptr) {
			switch network {
			case "tcp4", "udp4":
				innerErr = bindSocketToInterface4(windows.Handle(fd), uint32(ifaceIdx))
			case "tcp6", "udp6":
				innerErr = bindSocketToInterface6(windows.Handle(fd), uint32(ifaceIdx))
				if network == "udp6" && !addrPort.IsValid() {
					// The underlying IP net maybe IPv4 even if the `network` param is `udp6`,
					// so we should bind socket to interface4 at the same time.
					innerErr = bindSocketToInterface4(windows.Handle(fd), uint32(ifaceIdx))
				}
			}
		})

		if innerErr != nil {
			err = innerErr
		}

		return
	}
}

func bindSocketToInterface4(handle windows.Handle, index uint32) error {
	// For IPv4, this parameter must be an interface index in network byte order.
	// Ref: https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, index)
	index = byteorder.Native.Uint32(buf)
	return windows.SetsockoptInt(handle, windows.IPPROTO_IP, ipUnicastIf, int(index))
}

func bindSocketToInterface6(handle windows.Handle, index uint32) error {
	return windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, ipv6UnicastIf, int(index))
}

func bindIfaceToDialer(ifaceName string, dialer *net.Dialer, _ string, _ netip.Addr) error {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return err
	}

	dialer.Control = bindControl(ifaceObj.Index, dialer.Control)
	return nil
}

func bindIfaceToListenConfig(ifaceName string, lc *net.ListenConfig, _, address string) (string, error) {
	ifaceObj, err := iface.ResolveInterface(ifaceName)
	if err != nil {
		return "", err
	}

	lc.Control = bindControl(ifaceObj.Index, lc.Control)
	return address, nil
}

func WithBindToInterfaceControlFn(interfaceName string) func(network, address string, c syscall.RawConn) (err error) {
	return func(network, address string, c syscall.RawConn) (err error) {
		if interfaceName == "" {
			return nil
		}

		var (
			innerErr error
			ifaceObj *iface.Interface
		)

		ifaceObj, err = iface.ResolveInterface(interfaceName)
		if err != nil {
			return
		}

		err = c.Control(func(fd uintptr) {
			switch network {
			case "udp4":
				innerErr = bindSocketToInterface4(windows.Handle(fd), uint32(ifaceObj.Index))
			case "udp6":
				innerErr = bindSocketToInterface6(windows.Handle(fd), uint32(ifaceObj.Index))
				if innerErr != nil {
					innerErr = syscall.EAFNOSUPPORT
					return
				}
			}
		})

		if innerErr != nil {
			err = innerErr
		}

		return
	}
}
