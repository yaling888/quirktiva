package constant

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/transport/socks5"
)

// Socks addr type
const (
	TCP NetWork = iota
	UDP
	ALLNet
)

const (
	HTTP Type = iota
	HTTPCONNECT
	SOCKS4
	SOCKS5
	REDIR
	TPROXY
	TUN
	MITM
	TUNNEL
	XDP
	TAP
	MITM_ALL
)

type NetWork int

func (n NetWork) String() string {
	switch n {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return "all"
}

func (n NetWork) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.String())
}

type Type int

func (t Type) String() string {
	switch t {
	case HTTP:
		return "HTTP"
	case HTTPCONNECT:
		return "HTTP Connect"
	case SOCKS4:
		return "Socks4"
	case SOCKS5:
		return "Socks5"
	case REDIR:
		return "Redir"
	case TPROXY:
		return "TProxy"
	case TUN:
		return "TUN"
	case MITM:
		return "MITM"
	case TUNNEL:
		return "Tunnel"
	case XDP:
		return "XDP"
	case TAP:
		return "TAP"
	default:
		return "Unknown"
	}
}

func (t Type) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// Metadata is used to store connection address
type Metadata struct {
	NetWork      NetWork    `json:"network"`
	Type         Type       `json:"type"`
	SrcIP        netip.Addr `json:"sourceIP"`
	DstIP        netip.Addr `json:"destinationIP"`
	SrcPort      Port       `json:"sourcePort"`
	DstPort      Port       `json:"destinationPort"`
	Host         string     `json:"host"`
	DNSMode      DNSMode    `json:"dnsMode"`
	Process      string     `json:"process"`
	ProcessPath  string     `json:"processPath"`
	UserAgent    string     `json:"userAgent"`
	SpecialProxy string     `json:"specialProxy"`
	SNI          string     `json:"sni"`
	IsECH        bool       `json:"isECH"`

	OriginDst netip.AddrPort `json:"-"`
}

func (m *Metadata) RemoteAddress() string {
	return net.JoinHostPort(m.String(), m.DstPort.String())
}

func (m *Metadata) SourceAddress() string {
	return net.JoinHostPort(m.SrcIP.String(), m.SrcPort.String())
}

func (m *Metadata) AddrType() int {
	switch true {
	case m.DstIP.Is4():
		return socks5.AtypIPv4
	case m.DstIP.Is6():
		return socks5.AtypIPv6
	default:
		return socks5.AtypDomainName
	}
}

func (m *Metadata) Resolved() bool {
	return m.DstIP.IsValid()
}

func (m *Metadata) UDPAddr() *net.UDPAddr {
	if m.NetWork != UDP || !m.DstIP.IsValid() {
		return nil
	}
	return &net.UDPAddr{
		IP:   m.DstIP.AsSlice(),
		Port: int(m.DstPort),
	}
}

func (m *Metadata) String() string {
	if m.Host != "" {
		return m.Host
	} else if m.DstIP.IsValid() {
		return m.DstIP.String()
	} else {
		return "<nil>"
	}
}

func (m *Metadata) Valid() bool {
	return m.Host != "" || m.DstIP.IsValid()
}

func (m *Metadata) NetworkFromString(s string) {
	switch strings.ToLower(s) {
	case "tcp":
		m.NetWork = TCP
	case "udp":
		m.NetWork = UDP
	default:
		m.NetWork = ALLNet
	}
}

func (m *Metadata) MarshalObject(e *log.Entry) {
	if e == nil {
		return
	}

	e.Str("lAddr", m.SourceAddress())

	host := ""
	if m.DstIP.Is4() {
		host = m.DstIP.String()
	} else if m.DstIP.Is6() {
		host = "[" + m.DstIP.String() + "]"
	}

	if m.Host != "" {
		if host == "" {
			host = m.Host
		} else {
			host = m.Host + "(" + host + ")"
		}
	}

	e.Str("rAddr", host+":"+m.DstPort.String())

	if m.SNI != "" {
		e.Str("sni", m.SNI)
	}

	e.Bool("isECH", m.IsECH)
	e.Str("dnsMode", m.DNSMode.String())

	if m.Process != "" {
		e.Str("process", m.Process)
	}

	if m.UserAgent != "" {
		e.Str("userAgent", m.UserAgent)
	}
}

// Port is used to compatible with old version
type Port uint16

func (n Port) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.String())
}

func (n Port) String() string {
	return strconv.FormatUint(uint64(n), 10)
}

type LogAddr struct {
	M        Metadata
	Src      bool
	HostOnly bool
}

func (l LogAddr) String() string {
	if l.HostOnly {
		return l.M.String()
	}
	if !l.Src {
		return l.M.RemoteAddress()
	}
	return l.M.SourceAddress()
}
