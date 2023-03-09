package adapter

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Handler is a TCP/UDP connection handler that implements
// HandleTCPConn and HandleUDPConn methods.
type Handler interface {
	HandleTCP(net.Conn)
	HandleUDP(*stack.Stack, stack.TransportEndpointID, stack.PacketBufferPtr)
}

// TCPHandleFunc handles incoming TCP connection.
type TCPHandleFunc func(c net.Conn)

// UDPHandleFunc handles incoming UDP connection.
type UDPHandleFunc func(stack *stack.Stack, id stack.TransportEndpointID, pkt stack.PacketBufferPtr)
