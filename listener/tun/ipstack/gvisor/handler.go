package gvisor

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/phuslu/log"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	D "github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor/adapter"
)

var _ adapter.Handler = (*gvHandler)(nil)

type gvHandler struct {
	gateway   netip.Addr
	broadcast netip.Addr
	dnsHijack []C.DNSUrl

	tcpIn chan<- C.ConnContext
	udpIn chan<- *inbound.PacketAdapter
}

func (gh *gvHandler) HandleTCP(tunConn net.Conn) {
	var (
		lAddrPort netip.AddrPort
		rAddrPort netip.AddrPort
	)
	if ap, ok := tunConn.RemoteAddr().(*net.TCPAddr); ok {
		lAddrPort = ap.AddrPort()
	}
	if ap, ok := tunConn.LocalAddr().(*net.TCPAddr); ok {
		rAddrPort = ap.AddrPort()
	}

	if !lAddrPort.IsValid() || !rAddrPort.IsValid() {
		log.Debug().Msg("[GVisor] tcp endpoint not connected")
		_ = tunConn.Close()
		return
	}

	if D.ShouldHijackDns(gh.dnsHijack, rAddrPort, "tcp") {
		go func(dnsConn net.Conn, addr string) {
			log.Debug().Str("addr", addr).Msg("[TUN] hijack tcp dns")

			defer func(c net.Conn) {
				_ = c.Close()
			}(dnsConn)

			err1 := dnsConn.SetReadDeadline(time.Now().Add(C.DefaultTCPTimeout))
			if err1 != nil {
				return
			}

			buf := pool.NewBuffer()
			defer buf.Release()

			length, err1 := buf.ReadUint16be(dnsConn)
			if err1 != nil {
				return
			}

			_, err1 = buf.ReadFullFrom(dnsConn, int64(length))
			if err1 != nil {
				return
			}

			msg, err1 := D.RelayDnsPacket(buf.Bytes())
			if err1 != nil {
				return
			}

			buf.Reset()

			length = uint16(len(msg))
			_ = binary.Write(buf, binary.BigEndian, length)

			_, err1 = buf.Write(msg)
			if err1 != nil {
				return
			}

			_, _ = buf.WriteTo(dnsConn)
		}(tunConn, rAddrPort.String())

		return
	}

	gh.tcpIn <- inbound.NewSocketBy(tunConn, lAddrPort, rAddrPort, C.TUN)
}

func (gh *gvHandler) HandleUDP(stack *stack.Stack, id stack.TransportEndpointID, pkt stack.PacketBufferPtr) {
	defer pkt.DecRef()

	rAddr, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		log.Debug().Msg("[GVisor] udp endpoint not connected")
		return
	}
	rAddrPort := netip.AddrPortFrom(rAddr.Unmap(), id.LocalPort)

	if rAddrPort.Addr() == gh.gateway || rAddrPort.Addr() == gh.broadcast {
		return
	}

	lAddr, ok := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	if !ok {
		log.Debug().Msg("[GVisor] udp endpoint not connected")
		return
	}
	lAddrPort := netip.AddrPortFrom(lAddr.Unmap(), id.RemotePort)

	data := pkt.ToView()
	headerSize := pkt.HeaderSize()
	if data.Size() <= headerSize {
		return
	}

	data.TrimFront(headerSize)

	nicID := pkt.NICID

	if D.ShouldHijackDns(gh.dnsHijack, rAddrPort, "udp") {
		go func() {
			log.Debug().Str("addr", rAddrPort.String()).Msg("[TUN] hijack udp dns")

			defer data.Release()

			msg, err := D.RelayDnsPacket(data.AsSlice())
			if err != nil {
				return
			}

			conn, err := dialUDP(stack, nicID, rAddrPort, lAddrPort)
			if err != nil {
				return
			}

			_, _ = conn.Write(msg)
			_ = conn.Close()
		}()
		return
	}

	udpPkt := &packet{
		stack: stack,
		nicID: nicID,
		lAddr: lAddrPort,
		data:  data,
	}

	select {
	case gh.udpIn <- inbound.NewPacketBy(udpPkt, lAddrPort, rAddrPort, C.TUN):
	default:
		log.Debug().
			NetIPAddrPort("lAddrPort", lAddrPort).
			NetIPAddrPort("rAddrPort", rAddrPort).
			Msg("[GVisor] drop udp packet, because inbound queue is full")
		udpPkt.Drop()
	}
}
