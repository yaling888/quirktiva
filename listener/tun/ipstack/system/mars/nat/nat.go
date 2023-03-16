package nat

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"

	dev "github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars/tcpip"
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
		bufferSize = 65535 + offset
	)

	tab := newTable()
	udp := &UDP{
		device:         device,
		closed:         make(chan struct{}),
		incomingPacket: make(chan *udpElement, 100),
		writeBuffs:     make([][]byte, 0, 1),
		udpElements: &sync.Pool{New: func() any {
			return new(udpElement)
		}},
	}

	tcp := &TCP{
		listener: listener,
		portal:   portal,
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
			count      = 0
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

					if ipv4.Flags()&tcpip.FlagMoreFragment != 0 {
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

							writeBuffs = append(writeBuffs, raw)
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
