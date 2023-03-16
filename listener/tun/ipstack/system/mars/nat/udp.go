package nat

import (
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/bufferv2"

	dev "github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars/tcpip"
)

type udpElement struct {
	packet      *bufferv2.View
	source      netip.AddrPort
	destination netip.AddrPort
}

func (c *udpElement) clearPointers() {
	c.packet.Release()
	c.packet = nil
}

type UDP struct {
	device         dev.Device
	udpElements    *sync.Pool
	incomingPacket chan *udpElement
	writeBuff      [65535]byte
	writeBuffs     [][]byte
	writeLock      sync.Mutex
	closed         chan struct{}
	closedOnce     sync.Once
}

func (u *UDP) ReadFrom(buf []byte) (n int, src netip.AddrPort, dest netip.AddrPort, err error) {
	elem, ok := <-u.incomingPacket
	if !ok {
		err = net.ErrClosed
		return
	}

	defer u.putUDPElement(elem)

	n = copy(buf, elem.packet.AsSlice())
	if n < elem.packet.Size() {
		err = io.ErrShortBuffer
		return
	}

	src = elem.source
	dest = elem.destination
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
		close(u.incomingPacket)
		close(u.closed)
	})
	return nil
}

func (u *UDP) handleUDPPacket(ip tcpip.IP, pkt tcpip.UDPPacket) {
	if len(pkt.Payload()) == 0 {
		return
	}

	elem := u.getUDPElement()
	elem.packet = bufferv2.NewViewWithData(pkt.Payload())

	elem.source = netip.AddrPortFrom(ip.SourceIP(), pkt.SourcePort())
	elem.destination = netip.AddrPortFrom(ip.DestinationIP(), pkt.DestinationPort())

	u.incomingPacket <- elem
}

func (u *UDP) getUDPElement() *udpElement {
	return u.udpElements.Get().(*udpElement)
}

func (u *UDP) putUDPElement(elem *udpElement) {
	elem.clearPointers()
	u.udpElements.Put(elem)
}
