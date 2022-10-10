package gvisor

import (
	"net"

	"github.com/phuslu/log"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor/adapter"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor/option"
)

func withUDPHandler(handle adapter.UDPHandleFunc) option.Option {
	return func(s *stack.Stack) error {
		udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
			var (
				wq waiter.Queue
				id = r.ID()
			)
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				log.Warn().
					Str("error", err.String()).
					Str("rAddr", id.RemoteAddress.String()).
					Uint16("rPort", id.RemotePort).
					Str("lAddr", id.LocalAddress.String()).
					Uint16("lPort", id.LocalPort).
					Msg("[gVisor] forward udp request failed")
				return
			}

			conn := &udpConn{
				UDPConn: gonet.NewUDPConn(s, &wq, ep),
				id:      id,
			}
			handle(conn)
		})
		s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
		return nil
	}
}

type udpConn struct {
	*gonet.UDPConn
	id stack.TransportEndpointID
}

func (c *udpConn) ID() *stack.TransportEndpointID {
	return &c.id
}

func (c *udpConn) LocalAddr() net.Addr {
	return &net.UDPAddr{
		IP:   net.IP(c.id.LocalAddress),
		Port: int(c.id.LocalPort),
	}
}

func (c *udpConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP:   net.IP(c.id.RemoteAddress),
		Port: int(c.id.RemotePort),
	}
}

type packet struct {
	pc      adapter.UDPConn
	rAddr   net.Addr
	payload []byte
	offset  int
}

func (c *packet) Data() []byte {
	return c.payload[:c.offset]
}

// WriteBack write UDP packet with source(ip, port) = `addr`
func (c *packet) WriteBack(b []byte, _ net.Addr) (n int, err error) {
	return c.pc.WriteTo(b, c.rAddr)
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return c.rAddr
}

func (c *packet) Drop() {
	_ = pool.Put(c.payload)
}
