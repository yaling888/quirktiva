package adapter

import "net"

// Handler is a TCP/UDP connection handler that implements
// HandleTCPConn and HandleUDPConn methods.
type Handler interface {
	HandleTCP(net.Conn)
	HandleUDP(net.PacketConn)
}

// TCPHandleFunc handles incoming TCP connection.
type TCPHandleFunc func(c net.Conn)

// UDPHandleFunc handles incoming UDP connection.
type UDPHandleFunc func(pc net.PacketConn)
