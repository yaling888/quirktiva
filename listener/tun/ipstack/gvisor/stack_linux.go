//go:build !nogvisor && linux

package gvisor

import (
	"errors"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/yaling888/quirktiva/adapter/inbound"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/commons"
	"github.com/yaling888/quirktiva/listener/tun/ipstack/gvisor/option"
)

func NewStack(
	dnsHijack []C.DNSUrl,
	tunAddress, tunAddress6 netip.Prefix,
	tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter,
	tp C.Type,
) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})

	handler := &gvHandler{
		gateway:   commons.GetFirstAvailableIP(tunAddress),
		gateway6:  commons.GetFirstAvailableIP(tunAddress6),
		dnsHijack: dnsHijack,
		tcpIn:     tcpIn,
		udpIn:     udpIn,
		tp:        tp,
	}

	opts := []option.Option{option.WithDefault()}

	opts = append(opts, withTCPHandler(handler.HandleTCP), withUDPHandler(handler.HandleUDP))

	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func CreateNICWithOptions(s *stack.Stack, endpoint stack.LinkEndpoint, nicID tcpip.NICID, nicOpts stack.NICOptions) error {
	if err := s.CreateNICWithOptions(nicID, endpoint, nicOpts); err != nil {
		return errors.New(err.String())
	}

	var opts []option.Option
	opts = append(opts,
		withPromiscuousMode(nicID, nicPromiscuousModeEnabled),
		withSpoofing(nicID, nicSpoofingEnabled),
		withRouteTable(nicID),
	)
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return err
		}
	}
	return nil
}
