package constant

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/transport/socks5"
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
}

// Socks addr type
const (
	TCP NetWork = iota
	UDP
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
)

type NetWork int

func (n NetWork) String() string {
	if n == TCP {
		return "tcp"
	} else if n == UDP {
		return "udp"
	}
	return "unknown"
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
		return "Tun"
	case MITM:
		return "Mitm"
	default:
		return "Unknown"
	}
}

func (t Type) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// Metadata is used to store connection address
type Metadata struct {
	NetWork     NetWork    `json:"network"`
	Type        Type       `json:"type"`
	SrcIP       netip.Addr `json:"sourceIP"`
	DstIP       netip.Addr `json:"destinationIP"`
	SrcPort     string     `json:"sourcePort"`
	DstPort     string     `json:"destinationPort"`
	Host        string     `json:"host"`
	DNSMode     DNSMode    `json:"dnsMode"`
	Process     string     `json:"process"`
	ProcessPath string     `json:"processPath"`
	UserAgent   string     `json:"userAgent"`
}

func (m *Metadata) RemoteAddress() string {
	return net.JoinHostPort(m.String(), m.DstPort)
}

func (m *Metadata) SourceAddress() string {
	return net.JoinHostPort(m.SrcIP.String(), m.SrcPort)
}

func (m *Metadata) AddrType() int {
	switch true {
	case m.Host != "" || !m.Resolved():
		return socks5.AtypDomainName
	case m.DstIP.Is4():
		return socks5.AtypIPv4
	default:
		return socks5.AtypIPv6
	}
}

func (m *Metadata) Resolved() bool {
	return m.DstIP.IsValid()
}

// Pure is used to solve unexpected behavior
// when dialing proxy connection in DNSMapping mode.
func (m *Metadata) Pure(isMitmOutbound bool) *Metadata {
	if !isMitmOutbound && m.DNSMode == DNSMapping && m.DstIP.IsValid() {
		copyM := *m
		copyM.Host = ""
		return &copyM
	}

	return m
}

func (m *Metadata) UDPAddr() *net.UDPAddr {
	if m.NetWork != UDP || !m.DstIP.IsValid() {
		return nil
	}
	port, _ := strconv.ParseUint(m.DstPort, 10, 16)
	return &net.UDPAddr{
		IP:   m.DstIP.AsSlice(),
		Port: int(port),
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
		m.NetWork = -1
	}
}
