package tunnel

import (
	"fmt"
	"net"

	"github.com/yaling888/quirktiva/adapter/inbound"
	"github.com/yaling888/quirktiva/common/pool"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/socks5"
)

type PacketConn struct {
	conn   net.PacketConn
	addr   string
	target socks5.Addr
	proxy  string
	closed bool
}

// RawAddress implements C.Listener
func (l *PacketConn) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *PacketConn) Address() string {
	return l.conn.LocalAddr().String()
}

// Close implements C.Listener
func (l *PacketConn) Close() error {
	l.closed = true
	return l.conn.Close()
}

func NewUDP(addr, target, proxy string, in chan<- *inbound.PacketAdapter) (*PacketConn, error) {
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	targetAddr := socks5.ParseAddr(target)
	if targetAddr == nil {
		return nil, fmt.Errorf("invalid target address %s", target)
	}

	sl := &PacketConn{
		conn:   l,
		target: targetAddr,
		proxy:  proxy,
		addr:   addr,
	}
	go func() {
		for {
			bufP := pool.GetNetBuf()
			n, remoteAddr, err := l.ReadFrom(*bufP)
			if err != nil {
				pool.PutNetBuf(bufP)
				if sl.closed {
					break
				}
				continue
			}
			*bufP = (*bufP)[:n]
			sl.handleUDP(l, in, bufP, remoteAddr)
		}
	}()

	return sl, nil
}

func (l *PacketConn) handleUDP(pc net.PacketConn, in chan<- *inbound.PacketAdapter, bufP *[]byte, addr net.Addr) {
	pkt := &packet{
		pc:      pc,
		rAddr:   addr,
		payload: bufP,
	}

	ctx := inbound.NewPacket(l.target, pc.LocalAddr(), pkt, C.TUNNEL)
	ctx.Metadata().SpecialProxy = l.proxy
	select {
	case in <- ctx:
	default:
		pkt.Drop()
	}
}
