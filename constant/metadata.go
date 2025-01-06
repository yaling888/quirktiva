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

var MetadataTypeMapping = map[string]Type{
	strings.ToLower(HTTP.String()):        HTTP,
	strings.ToLower(HTTPCONNECT.String()): HTTPCONNECT,
	strings.ToLower(SOCKS4.String()):      SOCKS4,
	strings.ToLower(SOCKS5.String()):      SOCKS5,
	strings.ToLower(REDIR.String()):       REDIR,
	strings.ToLower(TPROXY.String()):      TPROXY,
	strings.ToLower(TUN.String()):         TUN,
	strings.ToLower(MITM.String()):        MITM,
	strings.ToLower(TUNNEL.String()):      TUNNEL,
}

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
)

type NetWork int

func (n NetWork) String() string {
	if n == TCP {
		return "tcp"
	} else if n == UDP {
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

func (m *Metadata) TypeFromString(s string) {
	if _type, ok := MetadataTypeMapping[strings.ToLower(s)]; ok {
		m.Type = _type
	} else {
		m.Type = -1
	}
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

	e.Str("rAddr", host+":"+m.DstPort.String()).Str("dnsMode", m.DNSMode.String())

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
