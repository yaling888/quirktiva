package nat

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"

	dev "github.com/yaling888/quirktiva/listener/tun/device"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/system/mars/tcpip"
)

const bufSize = 64 << 10

func Start(device dev.Device, gateway, portal, _ netip.Addr) (*TCP, *UDP, error) {
	listener, err := net.ListenTCP("tcp", nil)
	if err != nil {
		return nil, nil, err
	}

	gateway4 := gateway
	gateway6 := gateway
	portal4 := portal
	portal6 := portal
	if gateway6.Is6() {
		gateway4 = netip.AddrFrom4([4]byte{198, 18, 0, 1})
		portal4 = gateway4.Next()
	} else {
		gateway6 = netip.AddrFrom16([16]byte{'f', 'c', 'k', 'q', 'u', 'i', 'r', 'k', 't', 'i', 'v', 'a', 0, 0, 0, 1})
		portal6 = gateway6.Next()
	}

	var (
		offset     = device.Offset()
		batchSize  = device.BatchSize()
		bufferSize = bufSize + offset
	)

	bufferSize += 7 - ((bufferSize + 7) % 8)

	tab := newTable()
	udp := &UDP{
		device:         device,
		closed:         make(chan struct{}),
		incomingPacket: make(chan *UDPElement, 128),
		writeBufs:      make([][]byte, 0, 1),
		udpElements: &sync.Pool{New: func() any {
			b := make([]byte, bufSize)
			return &UDPElement{
				Packet: &b,
			}
		}},
	}

	tcp := &TCP{
		listener: listener,
		portal4:  portal4,
		portal6:  portal6,
		table:    tab,
	}

	gatewayPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	// read from tun device
	go func() {
		defer func() {
			_ = tcp.Close()
			_ = udp.Close()
		}()

		var (
			readErr    error
			count      int
			readBuffs  = make([][]byte, batchSize)
			writeBuffs = make([][]byte, 0, batchSize)
			sizes      = make([]int, batchSize)
		)

		for i := range readBuffs {
			readBuffs[i] = make([]byte, bufferSize)
		}

		for {
			count, readErr = device.Read(readBuffs, sizes, offset)
			for i := 0; i < count; i++ {
				if sizes[i] < 1 {
					continue
				}

				raw := readBuffs[i][:offset+sizes[i]]

				var (
					ipVersion int
					ip        tcpip.IP
				)

				ipVersion = tcpip.IPVersion(raw[offset:])

				switch ipVersion {
				case tcpip.IPv4Version:
					ipv4 := tcpip.IPv4Packet(raw[offset:])
					if !ipv4.Valid() {
						continue
					}

					if ipv4.TimeToLive() == 0x00 {
						continue
					}

					if (ipv4.Flags() & tcpip.FlagMoreFragment) != 0 {
						continue
					}

					if ipv4.FragmentOffset() != 0 {
						continue
					}

					ip = ipv4
				case tcpip.IPv6Version:
					ipv6 := tcpip.IPv6Packet(raw[offset:])
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

				if !destinationIP.IsGlobalUnicast() {
					continue
				}

				switch ip.Protocol() {
				case tcpip.TCP:
					t := tcpip.TCPPacket(ip.Payload())
					if !t.Valid() {
						continue
					}

					if (ipVersion == tcpip.IPv4Version && destinationIP == portal4) ||
						(ipVersion == tcpip.IPv6Version && destinationIP == portal6) {
						srcIP := ip.SourceIP()
						if (ipVersion == tcpip.IPv4Version && srcIP != gateway4) ||
							(ipVersion == tcpip.IPv6Version && srcIP != gateway6) || t.SourcePort() != gatewayPort {
							continue
						}

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

						writeBuffs = append(writeBuffs, raw)
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

						if ipVersion == tcpip.IPv4Version {
							ip.SetSourceIP(portal4)
							ip.SetDestinationIP(gateway4)
						} else {
							ip.SetSourceIP(portal6)
							ip.SetDestinationIP(gateway6)
						}
						t.SetSourcePort(port)
						t.SetDestinationPort(gatewayPort)

						ip.ResetChecksum()
						t.ResetChecksum(ip.PseudoSum())

						writeBuffs = append(writeBuffs, raw)
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

					writeBuffs = append(writeBuffs, raw)
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

					writeBuffs = append(writeBuffs, raw)
				}
			}

			if readErr != nil {
				if errors.Is(readErr, os.ErrClosed) {
					return
				}
				writeBuffs = writeBuffs[:0]
				continue
			}

			if len(writeBuffs) > 0 {
				_, _ = device.Write(writeBuffs, offset)
				writeBuffs = writeBuffs[:0]
			}
		}
	}()

	return tcp, udp, nil
}
