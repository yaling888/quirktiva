package autoredir

import (
	"net"
	"net/netip"

	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/adapter/inbound"
	"github.com/yaling888/quirktiva/common/pool"
	C "github.com/yaling888/quirktiva/constant"
)

type PacketConn struct {
	conn       net.PacketConn
	addr       string
	closed     bool
	lookupFunc func(netip.AddrPort) (netip.AddrPort, error)
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

func NewUDP(addr string, in chan<- *inbound.PacketAdapter, lookupFunc func(netip.AddrPort) (netip.AddrPort, error)) (*PacketConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	sl := &PacketConn{
		conn:       l,
		addr:       addr,
		lookupFunc: lookupFunc,
	}
	go func() {
		for {
			bufP := pool.GetNetBuf()
			n, remoteAddr, err := l.ReadFromUDPAddrPort(*bufP)
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

func (l *PacketConn) handleUDP(uc *net.UDPConn, in chan<- *inbound.PacketAdapter, bufP *[]byte, src netip.AddrPort) {
	dst, err := l.lookupFunc(src)
	if err != nil {
		log.Warn().Err(err).Msg("[Auto Redirect] handle udp")
		pool.PutNetBuf(bufP)
		return
	}

	if dst.Addr().Is4In6() {
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	}

	pkt := &packet{
		pc:      uc,
		rAddr:   src,
		payload: bufP,
	}

	ctx := inbound.NewPacketWithOriginDst(pkt, src, dst, uc.LocalAddr().(*net.UDPAddr).AddrPort(), C.REDIR)
	select {
	case in <- ctx:
	default:
		pkt.Drop()
	}
}
