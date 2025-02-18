package nat

import (
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"

	dev "github.com/yaling888/quirktiva/listener/tun/device"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/system/mars/tcpip"
)

type UDPElement struct {
	Packet      *[]byte
	Source      netip.AddrPort
	Destination netip.AddrPort
}

func (c *UDPElement) reset() {
	if c.Packet == nil {
		panic("Packet is nil")
	}
	if cap(*c.Packet) < bufSize {
		panic("invalid Packet capacity")
	}
	*c.Packet = (*c.Packet)[:bufSize]
}

type UDP struct {
	device         dev.Device
	udpElements    *sync.Pool
	incomingPacket chan *UDPElement
	writeBuf       [65535]byte
	writeBufs      [][]byte
	writeLock      sync.Mutex
	closed         chan struct{}
	closedOnce     sync.Once
}

func (u *UDP) ReadFrom() (ue *UDPElement, err error) {
	select {
	case <-u.closed:
		err = net.ErrClosed
	case ue = <-u.incomingPacket:
	}
	return
}

func (u *UDP) WriteTo(buf []byte, local netip.AddrPort, remote netip.AddrPort) (int, error) {
	select {
	case <-u.closed:
		return 0, net.ErrClosed
	default:
	}

	bufLen := len(buf)
	if bufLen == 0 {
		return 0, &net.OpError{
			Op:     "write",
			Net:    "udp",
			Source: net.UDPAddrFromAddrPort(local),
			Addr:   net.UDPAddrFromAddrPort(remote),
			Err:    errors.New("send data is empty"),
		}
	}

	if local.Addr().Is4In6() {
		local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	}

	if remote.Addr().Is4In6() {
		remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	}

	var (
		ip     tcpip.IP
		ipLen  int
		offset = u.device.Offset()
	)

	u.writeLock.Lock()
	defer u.writeLock.Unlock()

	if local.Addr().Is6() || remote.Addr().Is6() {
		ipLen = bufLen + offset + tcpip.IPv6MinimumSize + tcpip.UDPHeaderSize
		if ipLen > 0xffff {
			return 0, &net.OpError{
				Op:     "write",
				Net:    "udp",
				Source: net.UDPAddrFromAddrPort(local),
				Addr:   net.UDPAddrFromAddrPort(remote),
				Err:    errors.New("send data is too large"),
			}
		}
		tcpip.SetIPv6(u.writeBuf[offset:])
		ip6 := tcpip.IPv6Packet(u.writeBuf[offset:])
		ip6.SetTOS(0, 0)
		ip6.SetPayloadLength(tcpip.UDPHeaderSize + uint16(bufLen))
		ip6.SetHopLimit(64)
		ip = ip6
	} else {
		ipLen = bufLen + offset + tcpip.IPv4HeaderSize + tcpip.UDPHeaderSize
		if ipLen > 0xffff {
			return 0, &net.OpError{
				Op:     "write",
				Net:    "udp",
				Source: net.UDPAddrFromAddrPort(local),
				Addr:   net.UDPAddrFromAddrPort(remote),
				Err:    errors.New("send data is too large"),
			}
		}
		tcpip.SetIPv4(u.writeBuf[offset:])
		ip4 := tcpip.IPv4Packet(u.writeBuf[offset:])
		ip4.SetHeaderLen(tcpip.IPv4HeaderSize)
		ip4.SetTotalLength(tcpip.IPv4HeaderSize + tcpip.UDPHeaderSize + uint16(bufLen))
		ip4.SetTypeOfService(0)
		ip4.SetIdentification(uint16(rand.Uint32()))
		ip4.SetFragmentOffset(0)
		ip4.SetTimeToLive(64)
		ip = ip4
	}

	ip.SetProtocol(tcpip.UDP)
	ip.SetSourceIP(local.Addr())
	ip.SetDestinationIP(remote.Addr())

	udp := tcpip.UDPPacket(ip.Payload())
	udp.SetLength(tcpip.UDPHeaderSize + uint16(bufLen))
	udp.SetSourcePort(local.Port())
	udp.SetDestinationPort(remote.Port())

	n := copy(udp.Payload(), buf)
	if n < bufLen {
		return n, io.ErrShortWrite
	}

	ip.ResetChecksum()
	udp.ResetChecksum(ip.PseudoSum())

	u.writeBufs = append(u.writeBufs, u.writeBuf[:ipLen])
	_, err := u.device.Write(u.writeBufs, offset)
	u.writeBufs = u.writeBufs[:0]

	return n, err
}

func (u *UDP) Close() error {
	u.closedOnce.Do(func() {
		close(u.closed)
		u.flushPacketQueue()
	})
	return nil
}

func (u *UDP) handleUDPPacket(ip tcpip.IP, pkt tcpip.UDPPacket) {
	if len(pkt.Payload()) == 0 {
		return
	}

	elem := u.getUDPElement()
	n := copy(*elem.Packet, pkt.Payload())
	*elem.Packet = (*elem.Packet)[:n]

	elem.Source = netip.AddrPortFrom(ip.SourceIP(), pkt.SourcePort())
	elem.Destination = netip.AddrPortFrom(ip.DestinationIP(), pkt.DestinationPort())

	u.incomingPacket <- elem
}

func (u *UDP) getUDPElement() *UDPElement {
	return u.udpElements.Get().(*UDPElement)
}

func (u *UDP) PutUDPElement(elem *UDPElement) {
	elem.reset()
	u.udpElements.Put(elem)
}

func (u *UDP) flushPacketQueue() {
	for {
		select {
		case elem := <-u.incomingPacket:
			u.PutUDPElement(elem)
		default:
			return
		}
	}
}
