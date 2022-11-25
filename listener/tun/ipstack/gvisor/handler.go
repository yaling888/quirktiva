package gvisor

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/phuslu/log"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	D "github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor/adapter"
	"github.com/Dreamacro/clash/transport/socks5"
)

var _ adapter.Handler = (*gvHandler)(nil)

type gvHandler struct {
	gateway   netip.Addr
	broadcast netip.Addr
	dnsHijack []C.DNSUrl

	tcpIn chan<- C.ConnContext
	udpIn chan<- *inbound.PacketAdapter
}

func (gh *gvHandler) HandleTCP(tunConn adapter.TCPConn) {
	rAddrPort := tunConn.LocalAddr().(*net.TCPAddr).AddrPort()

	if D.ShouldHijackDns(gh.dnsHijack, rAddrPort, "tcp") {
		go func(dnsConn net.Conn, addr string) {
			log.Debug().
				Str("addr", addr).
				Msg("[TUN] hijack tcp dns")

			defer func(c net.Conn) {
				_ = c.Close()
			}(dnsConn)

			var err1 error
			err1 = dnsConn.SetReadDeadline(time.Now().Add(C.DefaultTCPTimeout))
			if err1 != nil {
				return
			}

			buf := pool.NewBuffer()
			defer buf.Release()

			_, err1 = buf.ReadFullFrom(dnsConn, 2)
			if err1 != nil {
				return
			}

			length := binary.BigEndian.Uint16(buf.Next(2))
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

	gh.tcpIn <- inbound.NewSocket(socks5.AddrFromStdAddrPort(rAddrPort), tunConn, C.TUN)
}

func (gh *gvHandler) HandleUDP(tunConn adapter.UDPConn) {
	rAddrPort := tunConn.LocalAddr().(*net.UDPAddr).AddrPort()

	if rAddrPort.Addr() == gh.gateway || rAddrPort.Addr() == gh.broadcast {
		_ = tunConn.Close()
		return
	}

	target := socks5.AddrFromStdAddrPort(rAddrPort)

	go func() {
		for {
			buf := pool.Get(pool.UDPBufferSize)

			n, addr, err := tunConn.ReadFrom(buf)
			if err != nil {
				_ = pool.Put(buf)
				break
			}

			if D.ShouldHijackDns(gh.dnsHijack, rAddrPort, "udp") {
				go func(dnsUdp adapter.UDPConn, b []byte, length int, rAddr net.Addr, rAddrStr string) {
					defer func(udp adapter.UDPConn, bb []byte) {
						_ = udp.Close()
						_ = pool.Put(bb)
					}(dnsUdp, b)

					msg, err1 := D.RelayDnsPacket(b[:length])
					if err1 != nil {
						return
					}

					_, _ = dnsUdp.WriteTo(msg, rAddr)

					log.Debug().
						Str("addr", rAddrStr).
						Msg("[TUN] hijack udp dns")
				}(tunConn, buf, n, addr, rAddrPort.String())

				continue
			}

			gvPacket := &packet{
				pc:      tunConn,
				rAddr:   addr,
				payload: buf,
				offset:  n,
			}

			select {
			case gh.udpIn <- inbound.NewPacket(target, gvPacket, C.TUN):
			default:
				gvPacket.Drop()
			}
		}
	}()
}
