package socks

import (
	"net"

	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/adapter/inbound"
	"github.com/yaling888/quirktiva/common/pool"
	"github.com/yaling888/quirktiva/common/sockopt"
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

	if err := sockopt.UDPReuseaddr(l.(*net.UDPConn)); err != nil {
		log.Warn().Err(err).Msg("[SOCKS] reuse UDP address failed")
	}

	sl := &UDPListener{
		packetConn: l,
		addr:       addr,
	}
	go func() {
		buf := make([]byte, pool.NetBufferSize)
		for {
			n, remoteAddr, err := l.ReadFrom(buf)
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			handleSocksUDP(l, in, buf[:n], remoteAddr)
		}
	}()

	return sl, nil
}

func handleSocksUDP(pc net.PacketConn, in chan<- *inbound.PacketAdapter, buf []byte, addr net.Addr) {
	target, payload, err := socks5.DecodeUDPPacket(buf)
	if err != nil {
		return
	}
	bufP := pool.GetNetBuf()
	n := copy(*bufP, payload)
	*bufP = (*bufP)[:n]
	pkt := &packet{
		pc:      pc,
		rAddr:   addr,
		payload: bufP,
	}
	select {
	case in <- inbound.NewPacket(target, pc.LocalAddr(), pkt, C.SOCKS5):
	default:
		pkt.Drop()
	}
}
