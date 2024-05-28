package nat

import (
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
	writeBuff      [65535]byte
	writeBuffs     [][]byte
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

	u.writeLock.Lock()
	defer u.writeLock.Unlock()

	offset := u.device.Offset()
	bufLen := len(buf)
	bufSize := bufLen + offset + tcpip.IPv4HeaderSize + tcpip.UDPHeaderSize

	if bufLen == 0 || bufSize > 0xfffe {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	if !local.Addr().Is4() || !remote.Addr().Is4() {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	tcpip.SetIPv4(u.writeBuff[offset:])

	ip := tcpip.IPv4Packet(u.writeBuff[offset:])
	ip.SetHeaderLen(tcpip.IPv4HeaderSize)
	ip.SetTotalLength(tcpip.IPv4HeaderSize + tcpip.UDPHeaderSize + uint16(bufLen))
	ip.SetTypeOfService(0)
	ip.SetIdentification(uint16(rand.Uint32()))
	ip.SetFragmentOffset(0)
	ip.SetTimeToLive(64)
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

	u.writeBuffs = append(u.writeBuffs, u.writeBuff[:bufSize])
	_, err := u.device.Write(u.writeBuffs, offset)
	u.writeBuffs = u.writeBuffs[:0]

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
