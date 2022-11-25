package system

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/phuslu/log"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/nnip"
	"github.com/Dreamacro/clash/common/pool"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	D "github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars/nat"
	"github.com/Dreamacro/clash/transport/socks5"
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
			_ = s.device.Close()
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
		_ = device.Close()

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
				}(conn, rAddrPort.String())

				continue
			}

			metadata := &C.Metadata{
				NetWork: C.TCP,
				Type:    C.TUN,
				SrcIP:   lAddrPort.Addr(),
				DstIP:   rAddrPort.Addr(),
				SrcPort: strconv.FormatUint(uint64(lAddrPort.Port()), 10),
				DstPort: strconv.FormatUint(uint64(rAddrPort.Port()), 10),
				Host:    "",
			}

			tcpIn <- context.NewConnContext(conn, metadata)
		}

		ipStack.wg.Done()
	}

	udp := func() {
		defer func(udp *nat.UDP) {
			_ = udp.Close()
		}(stack.UDP())

		for {
			buf := pool.Get(pool.UDPBufferSize)

			n, lAddrPort, rAddrPort, err0 := stack.UDP().ReadFrom(buf)
			if err0 != nil {
				_ = pool.Put(buf)

				if ipStack.closed {
					break
				}

				log.Warn().
					Err(err0).
					Msg("[Stack] accept udp failed")
				continue
			}

			if rAddrPort.Addr().IsLoopback() || rAddrPort.Addr() == gateway {
				_ = pool.Put(buf)

				continue
			}

			if D.ShouldHijackDns(dnsAddr, rAddrPort, "udp") {
				go func(dnsUdp *nat.UDP, b []byte, length int, rap, lap netip.AddrPort) {
					defer func(bb []byte) {
						_ = pool.Put(bb)
					}(b)

					msg, err1 := D.RelayDnsPacket(b[:length])
					if err1 != nil {
						return
					}

					_, _ = dnsUdp.WriteTo(msg, rap, lap)

					log.Debug().
						Str("addr", rap.String()).
						Msg("[TUN] hijack udp dns")
				}(stack.UDP(), buf, n, rAddrPort, lAddrPort)

				continue
			}

			pkt := &packet{
				local:  lAddrPort,
				data:   buf,
				offset: n,
				writeBack: func(b []byte, addr net.Addr) (int, error) {
					return stack.UDP().WriteTo(b, rAddrPort, lAddrPort)
				},
			}

			select {
			case udpIn <- inbound.NewPacket(socks5.AddrFromStdAddrPort(rAddrPort), pkt, C.TUN):
			default:
				pkt.Drop()
			}
		}

		ipStack.wg.Done()
	}

	ipStack.once.Do(func() {
		ipStack.wg.Add(1)
		go tcp()

		numUDPWorkers := 4
		if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
			numUDPWorkers = num
		}
		for i := 0; i < numUDPWorkers; i++ {
			ipStack.wg.Add(1)
			go udp()
		}
	})

	return ipStack, nil
}
