package commons

import (
	"net/netip"
	"time"

	D "github.com/miekg/dns"

	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
)

const ipv6Delay = time.Millisecond * 6 // delay response AAAA answer when disable IPv6

func ShouldHijackDns(dnsHijack []C.DNSUrl, targetAddr netip.AddrPort, network string) bool {
	for _, dns := range dnsHijack {
		if dns.Network == network && (dns.AddrPort.AddrPort == targetAddr ||
			(dns.AddrPort.Addr().IsUnspecified() && dns.AddrPort.Port() == targetAddr.Port())) {
			return true
		}
	}
	return false
}

func RelayDnsPacket(payload []byte) ([]byte, error) {
	msg := &D.Msg{}
	if err := msg.Unpack(payload); err != nil {
		return nil, err
	}

	if len(msg.Question) == 0 {
		return handleMsgWithEmptyAnswer(msg, D.RcodeBadName)
	}

	if resolver.DisableIPv6 && msg.Question[0].Qtype == D.TypeAAAA {
		time.Sleep(ipv6Delay)
		return handleMsgWithEmptyAnswer(msg, D.RcodeSuccess)
	}

	r, err := resolver.ServeMsg(msg)
	if err != nil {
		return handleMsgWithEmptyAnswer(msg, D.RcodeServerFailure)
	}

	r.SetRcode(msg, r.Rcode)
	r.Compress = true
	return r.Pack()
}

func handleMsgWithEmptyAnswer(r *D.Msg, code int) ([]byte, error) {
	msg := &D.Msg{}
	msg.Answer = []D.RR{}

	msg.SetRcode(r, code)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	return msg.Pack()
}
