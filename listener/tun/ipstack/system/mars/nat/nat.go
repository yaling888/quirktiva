package nat

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"

	"gvisor.dev/gvisor/pkg/bufferv2"

	dev "github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars/tcpip"
)

var (
	writeBackSlice *sync.Pool
	writeBackQueue *autoDrainingWriteBackQueue
	udpReadQueue   *autoDrainingCallQueue
)

func Start(device dev.Device, gateway, portal, broadcast netip.Addr) (*TCP, *UDP, error) {
	if !portal.Is4() || !gateway.Is4() {
		return nil, nil, net.InvalidAddrError("only ipv4 supported")
	}

	listener, err := net.ListenTCP("tcp4", nil)
	if err != nil {
		return nil, nil, err
	}

	var (
		offset     = device.Offset()
		batchSize  = device.BatchSize()
		bufferSize = int(device.MTU()) + offset
	)

	if bufferSize == 0 {
		bufferSize = 64 * 1024
	}

	tab := newTable()
	udp := &UDP{
		device: device,
		closed: make(chan struct{}),
		callElements: &sync.Pool{New: func() any {
			return new(call)
		}},
	}

	tcp := &TCP{
		listener: listener,
		portal:   portal,
		table:    tab,
	}

	writeBackQueue = newAutoDrainingWriteBackQueue()
	udpReadQueue = newAutoDrainingCallQueue(udp)

	writeBackSlice = &sync.Pool{New: func() any {
		s := make([]*bufferv2.View, 0, batchSize)
		return &s
	}}

	gatewayPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	// read from tun device
	go func() {
		defer func() {
			_ = tcp.Close()
			_ = udp.Close()
		}()

		var (
			readErr error
			count   = 0
			buffs   = make([][]byte, batchSize)
			sizes   = make([]int, batchSize)
		)

		for i := range buffs {
			buffs[i] = make([]byte, bufferSize)
		}

		for {
			var elems *[]*bufferv2.View
			count, readErr = device.Read(buffs, sizes, offset)
			for i := 0; i < count; i++ {
				if sizes[i] < 1 {
					continue
				}

				raw := buffs[i][offset : offset+sizes[i]]

				var (
					ipVersion int
					ip        tcpip.IP
				)

				ipVersion = tcpip.IPVersion(raw)

				switch ipVersion {
				case tcpip.IPv4Version:
					ipv4 := tcpip.IPv4Packet(raw)
					if !ipv4.Valid() {
						continue
					}

					if ipv4.TimeToLive() == 0x00 {
						continue
					}

					if ipv4.Flags()&tcpip.FlagMoreFragment != 0 {
						continue
					}

					if ipv4.FragmentOffset() != 0 {
						continue
					}

					ip = ipv4
				case tcpip.IPv6Version:
					ipv6 := tcpip.IPv6Packet(raw)
					if !ipv6.Valid() {
						continue
					}

					if ipv6.HopLimit() == 0x00 {
						continue
					}

					ip = ipv6
				default:
					continue
				}

				destinationIP := ip.DestinationIP()

				if !destinationIP.IsGlobalUnicast() || destinationIP == broadcast {
					continue
				}

				switch ip.Protocol() {
				case tcpip.TCP:
					t := tcpip.TCPPacket(ip.Payload())
					if !t.Valid() {
						continue
					}

					if destinationIP == portal {
						if ip.SourceIP() == gateway && t.SourcePort() == gatewayPort {
							tup := tab.tupleOf(t.DestinationPort())
							if tup == zeroTuple {
								continue
							}

							ip.SetSourceIP(tup.DestinationAddr.Addr())
							t.SetSourcePort(tup.DestinationAddr.Port())
							ip.SetDestinationIP(tup.SourceAddr.Addr())
							t.SetDestinationPort(tup.SourceAddr.Port())

							ip.DecTimeToLive()
							ip.ResetChecksum()
							t.ResetChecksum(ip.PseudoSum())

							elem := bufferv2.NewViewWithData(buffs[i][:offset+sizes[i]])
							if elems == nil {
								elems = getWriteBackSlice()
							}
							*elems = append(*elems, elem)
						}
					} else {
						tup := tuple{
							SourceAddr:      netip.AddrPortFrom(ip.SourceIP(), t.SourcePort()),
							DestinationAddr: netip.AddrPortFrom(destinationIP, t.DestinationPort()),
						}

						port := tab.portOf(tup)
						if port == 0 {
							if t.Flags() != tcpip.TCPSyn {
								continue
							}

							port = tab.newConn(tup)
						}

						ip.SetSourceIP(portal)
						ip.SetDestinationIP(gateway)
						t.SetSourcePort(port)
						t.SetDestinationPort(gatewayPort)

						ip.ResetChecksum()
						t.ResetChecksum(ip.PseudoSum())

						elem := bufferv2.NewViewWithData(buffs[i][:offset+sizes[i]])
						if elems == nil {
							elems = getWriteBackSlice()
						}
						*elems = append(*elems, elem)
					}
				case tcpip.UDP:
					u := tcpip.UDPPacket(ip.Payload())
					if !u.Valid() {
						continue
					}

					udp.handleUDPPacket(ip, u)
				case tcpip.ICMP:
					icmp := tcpip.ICMPPacket(ip.Payload())

					if icmp.Type() != tcpip.ICMPTypePingRequest || icmp.Code() != 0 {
						continue
					}

					icmp.SetType(tcpip.ICMPTypePingResponse)

					ip.SetDestinationIP(ip.SourceIP())
					ip.SetSourceIP(destinationIP)

					ip.ResetChecksum()
					icmp.ResetChecksum()

					elem := bufferv2.NewViewWithData(buffs[i][:offset+sizes[i]])
					if elems == nil {
						elems = getWriteBackSlice()
					}
					*elems = append(*elems, elem)
				case tcpip.ICMPv6:
					icmp6 := tcpip.ICMPv6Packet(ip.Payload())

					if icmp6.Type() != tcpip.ICMPv6EchoRequest || icmp6.Code() != 0 {
						continue
					}

					icmp6.SetType(tcpip.ICMPv6EchoReply)

					ip.SetDestinationIP(ip.SourceIP())
					ip.SetSourceIP(destinationIP)

					ip.ResetChecksum()
					icmp6.ResetChecksum(ip.PseudoSum())

					elem := bufferv2.NewViewWithData(buffs[i][:offset+sizes[i]])
					if elems == nil {
						elems = getWriteBackSlice()
					}
					*elems = append(*elems, elem)
				}
			}

			if readErr != nil {
				if elems != nil {
					for _, elem := range *elems {
						elem.Release()
					}
					putWriteBackSlice(elems)
				}
				if errors.Is(readErr, os.ErrClosed) {
					return
				}
				continue
			}

			if elems != nil {
				select {
				case writeBackQueue.c <- elems:
				default:
					for _, elem := range *elems {
						elem.Release()
					}
					putWriteBackSlice(elems)
				}
			}
		}
	}()

	// write to tun device
	go func() {
		buffs := make([][]byte, 0, batchSize)
		for {
			select {
			case elems := <-writeBackQueue.c:
				for _, elem := range *elems {
					buffs = append(buffs, elem.AsSlice())
				}
				if len(buffs) > 0 {
					_, _ = device.Write(buffs, offset)
				}
				for _, elem := range *elems {
					elem.Release()
				}
				buffs = buffs[:0]
				putWriteBackSlice(elems)
			case <-udp.wait():
				flushWriteBackQueue(writeBackQueue)
				return
			}
		}
	}()

	return tcp, udp, nil
}

func getWriteBackSlice() *[]*bufferv2.View {
	return writeBackSlice.Get().(*[]*bufferv2.View)
}

func putWriteBackSlice(s *[]*bufferv2.View) {
	for i := range *s {
		(*s)[i] = nil
	}
	*s = (*s)[:0]
	writeBackSlice.Put(s)
}

type autoDrainingWriteBackQueue struct {
	c chan *[]*bufferv2.View
}

func newAutoDrainingWriteBackQueue() *autoDrainingWriteBackQueue {
	q := &autoDrainingWriteBackQueue{
		c: make(chan *[]*bufferv2.View, 512),
	}
	runtime.SetFinalizer(q, flushWriteBackQueue)
	return q
}

func flushWriteBackQueue(q *autoDrainingWriteBackQueue) {
	for {
		select {
		case elems := <-q.c:
			for _, elem := range *elems {
				elem.Release()
			}
			putWriteBackSlice(elems)
		default:
			return
		}
	}
}
