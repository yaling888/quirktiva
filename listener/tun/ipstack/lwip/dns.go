package lwip

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/Dreamacro/clash/component/resolver"
	D "github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/log"
	"github.com/yaling888/go-lwip"
)

const defaultDnsReadTimeout = time.Second * 30

func shouldHijackDns(dnsIP net.IP, targetIp net.IP, targetPort int) bool {
	if targetPort != 53 {
		return false
	}

	return dnsIP.Equal(net.IPv4zero) || dnsIP.Equal(targetIp)
}

func hijackUDPDns(conn golwip.UDPConn, pkt []byte, addr *net.UDPAddr) {
	go func() {
		defer func(conn golwip.UDPConn) {
			_ = conn.Close()
		}(conn)

		answer, err := D.RelayDnsPacket(pkt)
		if err != nil {
			return
		}
		_, _ = conn.WriteFrom(answer, addr)
	}()
}

func hijackTCPDns(conn net.Conn) {
	go func() {
		defer func(conn net.Conn) {
			_ = conn.Close()
		}(conn)

		for {
			if err := conn.SetDeadline(time.Now().Add(defaultDnsReadTimeout)); err != nil {
				return
			}

			var length uint16
			if binary.Read(conn, binary.BigEndian, &length) != nil {
				return
			}

			data := make([]byte, length)

			_, err := io.ReadFull(conn, data)
			if err != nil {
				return
			}

			rb, err := D.RelayDnsPacket(data)
			if err != nil {
				continue
			}

			if binary.Write(conn, binary.BigEndian, uint16(len(rb))) != nil {
				return
			}

			if _, err := conn.Write(rb); err != nil {
				return
			}
		}
	}()
}

type dnsHandler struct{}

func NewDnsHandler() golwip.DnsHandler {
	return &dnsHandler{}
}

func (d dnsHandler) ResolveIP(host string) (net.IP, error) {
	log.Debugln("[TUN] lwip resolve ip for host: %s", host)
	return resolver.ResolveIP(host)
}