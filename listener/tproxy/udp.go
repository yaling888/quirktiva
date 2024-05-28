package tproxy

import (
	"net"
	"net/netip"

	"github.com/yaling888/quirktiva/adapter/inbound"
	"github.com/yaling888/quirktiva/common/pool"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/socks5"
)

type UDPListener struct {
	packetConn net.PacketConn
	addr       string
	closed     bool
}

// RawAddress implements C.Listener
func (l *UDPListener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *UDPListener) Address() string {
	return l.packetConn.LocalAddr().String()
}

// Close implements C.Listener
func (l *UDPListener) Close() error {
	l.closed = true
	return l.packetConn.Close()
}

func NewUDP(addr string, in chan<- *inbound.PacketAdapter) (C.Listener, error) {
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	rl := &UDPListener{
		packetConn: l,
		addr:       addr,
	}

	c := l.(*net.UDPConn)

	rc, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}

	err = setsockopt(rc, addr)
	if err != nil {
		return nil, err
	}

	go func() {
		oob := make([]byte, 1024)
		for {
			bufP := pool.GetNetBuf()
			n, oobn, _, lAddr, err := c.ReadMsgUDPAddrPort(*bufP, oob)
			if err != nil {
				pool.PutNetBuf(bufP)
				if rl.closed {
					break
				}
				continue
			}

			rAddr, err := getOrigDst(oob[:oobn])
			if err != nil {
				pool.PutNetBuf(bufP)
				continue
			}

			if rAddr.Addr().Is4() {
				// try to unmap 4in6 address
				lAddr = netip.AddrPortFrom(lAddr.Addr().Unmap(), lAddr.Port())
			}
			*bufP = (*bufP)[:n]
			handlePacketConn(in, bufP, lAddr, rAddr)
		}
	}()

	return rl, nil
}

func handlePacketConn(in chan<- *inbound.PacketAdapter, bufP *[]byte, lAddr, rAddr netip.AddrPort) {
	target := socks5.AddrFromStdAddrPort(rAddr)
	pkt := &packet{
		lAddr: lAddr,
		bufP:  bufP,
	}
	select {
	case in <- inbound.NewPacket(target, target.UDPAddr(), pkt, C.TPROXY):
	default:
		pkt.Drop()
	}
}
