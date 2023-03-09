package nat

import (
	"errors"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"sync"

	"gvisor.dev/gvisor/pkg/bufferv2"

	dev "github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars/tcpip"
)

type autoDrainingCallQueue struct {
	c chan *call
}

func newAutoDrainingCallQueue(u *UDP) *autoDrainingCallQueue {
	q := &autoDrainingCallQueue{
		c: make(chan *call, 512),
	}
	runtime.SetFinalizer(q, u.flushCallQueue)
	return q
}

type call struct {
	packet      *bufferv2.View
	source      netip.AddrPort
	destination netip.AddrPort
}

func (c *call) clearPointers() {
	c.packet.Release()
	c.packet = nil
	c.source = netip.AddrPort{}
	c.destination = netip.AddrPort{}
}

type UDP struct {
	device       dev.Device
	callElements *sync.Pool
	closed       chan struct{}
	closedOnce   sync.Once
}

func (u *UDP) ReadFrom(buf []byte) (n int, src netip.AddrPort, dest netip.AddrPort, err error) {
	select {
	case <-u.closed:
		err = net.ErrClosed
		return
	case elem := <-udpReadQueue.c:
		if elem == nil {
			err = errors.New("element is nil")
			return
		}

		defer u.putCallElement(elem)

		n = copy(buf, elem.packet.AsSlice())
		if n < elem.packet.Size() {
			err = io.ErrShortBuffer
			return
		}

		src = elem.source
		dest = elem.destination
		return
	}
}

func (u *UDP) WriteTo(buf []byte, local netip.AddrPort, remote netip.AddrPort) (int, error) {
	select {
	case <-u.closed:
		return 0, net.ErrClosed
	default:
	}

	offset := u.device.Offset()
	bufLen := len(buf)
	bufSize := bufLen + offset + tcpip.IPv4HeaderSize + tcpip.UDPHeaderSize

	if bufLen == 0 || bufSize > 0xfffe {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	if !local.Addr().Is4() || !remote.Addr().Is4() {
		return 0, net.InvalidAddrError("invalid ip version")
	}

	elem := bufferv2.NewViewSize(bufSize)
	buff := elem.AsSlice()[offset:]

	tcpip.SetIPv4(buff)

	ip := tcpip.IPv4Packet(buff)
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

	elems := getWriteBackSlice()
	*elems = append(*elems, elem)

	select {
	case writeBackQueue.c <- elems:
	default:
		elem.Release()
		putWriteBackSlice(elems)
		return 0, io.ErrShortWrite
	}

	return n, nil
}

func (u *UDP) Close() error {
	u.closedOnce.Do(func() {
		close(u.closed)
		u.flushCallQueue(udpReadQueue)
	})
	return nil
}

func (u *UDP) handleUDPPacket(ip tcpip.IP, pkt tcpip.UDPPacket) {
	if len(pkt.Payload()) == 0 {
		return
	}

	elem := u.getCallElement()
	elem.packet = bufferv2.NewViewWithData(pkt.Payload())

	elem.source = netip.AddrPortFrom(ip.SourceIP(), pkt.SourcePort())
	elem.destination = netip.AddrPortFrom(ip.DestinationIP(), pkt.DestinationPort())

	select {
	case udpReadQueue.c <- elem:
	default:
		u.putCallElement(elem)
	}
}

func (u *UDP) wait() chan struct{} {
	return u.closed
}

func (u *UDP) getCallElement() *call {
	return u.callElements.Get().(*call)
}

func (u *UDP) putCallElement(elem *call) {
	elem.clearPointers()
	u.callElements.Put(elem)
}

func (u *UDP) flushCallQueue(q *autoDrainingCallQueue) {
	for {
		select {
		case elem := <-q.c:
			u.putCallElement(elem)
		default:
			return
		}
	}
}
