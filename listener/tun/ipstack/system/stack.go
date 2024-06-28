package system

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/adapter/inbound"
	"github.com/yaling888/quirktiva/common/nnip"
	"github.com/yaling888/quirktiva/common/pool"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/device"
	"github.com/yaling888/quirktiva/listener/tun/ipstack"
	D "github.com/yaling888/quirktiva/listener/tun/ipstack/commons"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/system/mars"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/system/mars/nat"
)

type sysStack struct {
	stack  io.Closer
	device device.Device

	closed bool
	once   sync.Once
	wg     sync.WaitGroup
}

func (s *sysStack) Close() error {
	D.StopDefaultInterfaceChangeMonitor()

	defer func() {
		if s.device != nil {
			_ = s.device.Close2()
		}
	}()

	s.closed = true

	err := s.stack.Close()

	s.wg.Wait()

	return err
}

func New(device device.Device, dnsHijack []C.DNSUrl, tunAddress netip.Prefix, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (ipstack.Stack, error) {
	var (
		gateway   = tunAddress.Masked().Addr().Next()
		portal    = gateway.Next()
		broadcast = nnip.UnMasked(tunAddress)
	)

	stack, err := mars.StartListener(device, gateway, portal, broadcast)
	if err != nil {
		_ = device.Close2()

		return nil, err
	}

	ipStack := &sysStack{stack: stack, device: device}

	dnsAddr := dnsHijack

	tcp := func() {
		defer func(tcp *nat.TCP) {
			_ = tcp.Close()
		}(stack.TCP())

		for {
			conn, err0 := stack.TCP().Accept()
			if err0 != nil {
				if ipStack.closed {
					break
				}
				log.Warn().
					Err(err0).
					Msg("[Stack] accept connection failed")
				continue
			}

			lAddrPort := conn.LocalAddr().(*net.TCPAddr).AddrPort()
			rAddrPort := conn.RemoteAddr().(*net.TCPAddr).AddrPort()

			if rAddrPort.Addr().IsLoopback() {
				_ = conn.Close()

				continue
			}

			if D.ShouldHijackDns(dnsAddr, rAddrPort, "tcp") {
				go func(dnsConn net.Conn, addr netip.AddrPort) {
					log.Debug().NetIPAddrPort("addr", addr).Msg("[TUN] hijack tcp dns")

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
				}(conn, rAddrPort)

				continue
			}

			tcpIn <- inbound.NewSocketBy(conn, lAddrPort, rAddrPort, C.TUN)
		}

		ipStack.wg.Done()
	}

	udp := func() {
		defer func(udp *nat.UDP) {
			_ = udp.Close()
		}(stack.UDP())

		for {
			ue, err0 := stack.UDP().ReadFrom()
			if err0 != nil {
				if ipStack.closed {
					break
				}

				log.Warn().Err(err0).Msg("[Stack] accept udp failed")
				continue
			}

			rAddrPort := ue.Destination
			if rAddrPort.Addr().IsLoopback() || rAddrPort.Addr() == gateway {
				stack.UDP().PutUDPElement(ue)
				continue
			}

			if D.ShouldHijackDns(dnsAddr, rAddrPort, "udp") {
				go func() {
					defer stack.UDP().PutUDPElement(ue)

					log.Debug().NetIPAddrPort("addr", ue.Destination).Msg("[TUN] hijack udp dns")

					msg, err1 := D.RelayDnsPacket(*ue.Packet)
					if err1 != nil {
						return
					}

					_, _ = stack.UDP().WriteTo(msg, ue.Destination, ue.Source)
				}()

				continue
			}

			pkt := &packet{
				sender: stack.UDP(),
				data:   ue,
				lAddr:  ue.Source,
			}

			select {
			case udpIn <- inbound.NewPacketBy(pkt, ue.Source, rAddrPort, C.TUN):
			default:
				log.Debug().
					NetIPAddrPort("lAddrPort", ue.Source).
					NetIPAddrPort("rAddrPort", rAddrPort).
					Msg("[Stack] drop udp packet, because inbound queue is full")
				pkt.Drop()
			}
		}

		ipStack.wg.Done()
	}

	ipStack.once.Do(func() {
		ipStack.wg.Add(2)
		go tcp()
		go udp()
	})

	return ipStack, nil
}
