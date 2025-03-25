//go:build !nogvisor && linux

package tun

import (
	"crypto/rand"
	"net"
	"net/url"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/yaling888/quirktiva/adapter/inbound"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/ipstack"
)

// New TunAdapter
func New(
	tunConf *C.Tun,
	tcpIn chan<- C.ConnContext,
	udpIn chan<- *inbound.PacketAdapter,
	tunChangeCallback C.TUNChangeCallback,
) (ipstack.Stack, error) {
	var dev string
	if u, err := url.Parse(tunConf.Device); err == nil {
		dev = strings.ToUpper(u.Scheme)
	}

	switch dev {
	case "XDP":
		return newXDPAdapter(tunConf, tcpIn, udpIn)
	default:
	}

	return newTunAdapter(tunConf, tcpIn, udpIn, tunChangeCallback)
}

func randLinkAddress() []byte {
	linkAddress := make([]byte, 6)
	if _, err := rand.Read(linkAddress); err != nil {
		return linkAddress
	}
	linkAddress[0] &^= 0x1
	linkAddress[0] |= 0x2
	return linkAddress
}

func ipToAddressAndProto(ip net.IP) (tcpip.NetworkProtocolNumber, tcpip.Address) {
	if i4 := ip.To4(); i4 != nil {
		return ipv4.ProtocolNumber, tcpip.AddrFromSlice(i4)
	}
	return ipv6.ProtocolNumber, tcpip.AddrFromSlice(ip)
}
