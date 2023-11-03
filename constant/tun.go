package constant

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

var StackTypeMapping = map[string]TUNStack{
	strings.ToUpper(TunGvisor.String()): TunGvisor,
	strings.ToUpper(TunSystem.String()): TunSystem,
}

const (
	TunGvisor TUNStack = iota
	TunSystem
)

const (
	TunDisabled TUNState = iota
	TunEnabled
	TunPaused
)

type TUNState int

type TUNChangeCallback interface {
	Pause()
	Resume()
}

// Tun config
type Tun struct {
	Enable              bool          `yaml:"enable" json:"enable"`
	Device              string        `yaml:"device" json:"device"`
	Stack               TUNStack      `yaml:"stack" json:"stack"`
	DNSHijack           []DNSUrl      `yaml:"dns-hijack" json:"dns-hijack"`
	AutoRoute           bool          `yaml:"auto-route" json:"auto-route"`
	AutoDetectInterface bool          `yaml:"auto-detect-interface" json:"auto-detect-interface"`
	TunAddressPrefix    *netip.Prefix `yaml:"-" json:"-"`
	RedirectToTun       []string      `yaml:"-" json:"-"`
	StopRouteListener   bool          `yaml:"-" json:"-"`
}

var lastTunConf *Tun

func GetLastTunConf() *Tun {
	return lastTunConf
}

func SetLastTunConf(conf *Tun) {
	lastTunConf = conf
}

// GetTunConf returns the last tun config
func GetTunConf() Tun {
	if lastTunConf == nil {
		addrPort := DNSAddrPort{
			AddrPort: netip.MustParseAddrPort("0.0.0.0:53"),
		}
		return Tun{
			Enable: false,
			Stack:  TunGvisor,
			DNSHijack: []DNSUrl{ // default hijack all dns query
				{
					Network:  "udp",
					AddrPort: addrPort,
				},
				{
					Network:  "tcp",
					AddrPort: addrPort,
				},
			},
			AutoRoute:           true,
			AutoDetectInterface: false,
		}
	}
	return *lastTunConf
}

type TUNStack int

// UnmarshalYAML unserialize TUNStack with yaml
func (e *TUNStack) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	if err := unmarshal(&tp); err != nil {
		return err
	}
	mode, exist := StackTypeMapping[strings.ToUpper(tp)]
	if !exist {
		return errors.New("invalid tun stack")
	}
	*e = mode
	return nil
}

// MarshalYAML serialize TUNStack with yaml
func (e TUNStack) MarshalYAML() (any, error) {
	return e.String(), nil
}

// UnmarshalJSON unserialize TUNStack with json
func (e *TUNStack) UnmarshalJSON(data []byte) error {
	var tp string
	_ = json.Unmarshal(data, &tp)
	mode, exist := StackTypeMapping[strings.ToUpper(tp)]
	if !exist {
		return errors.New("invalid tun stack")
	}
	*e = mode
	return nil
}

// MarshalJSON serialize TUNStack with json
func (e TUNStack) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func (e TUNStack) String() string {
	switch e {
	case TunGvisor:
		return "gVisor"
	case TunSystem:
		return "System"
	default:
		return "unknown"
	}
}

type DNSAddrPort struct {
	netip.AddrPort
}

func (p *DNSAddrPort) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*p = DNSAddrPort{}
		return nil
	}

	addrPort := string(text)
	if strings.HasPrefix(addrPort, "any") {
		_, port, _ := strings.Cut(addrPort, "any")
		addrPort = "0.0.0.0" + port
	}

	ap, err := netip.ParseAddrPort(addrPort)
	*p = DNSAddrPort{AddrPort: ap}
	return err
}

func (p DNSAddrPort) String() string {
	addrPort := p.AddrPort.String()
	if p.AddrPort.Addr().IsUnspecified() {
		addrPort = "any:" + strconv.Itoa(int(p.AddrPort.Port()))
	}
	return addrPort
}

type DNSUrl struct {
	Network  string
	AddrPort DNSAddrPort
}

func (d *DNSUrl) UnmarshalYAML(unmarshal func(any) error) error {
	var text string
	if err := unmarshal(&text); err != nil {
		return err
	}

	text = strings.ToLower(text)
	network := "udp"
	if before, after, found := strings.Cut(text, "://"); found {
		network = before
		text = after
	}

	if network != "udp" && network != "tcp" {
		return errors.New("invalid dns url schema")
	}

	ap := &DNSAddrPort{}
	if err := ap.UnmarshalText([]byte(text)); err != nil {
		return err
	}

	*d = DNSUrl{Network: network, AddrPort: *ap}

	return nil
}

func (d DNSUrl) MarshalYAML() (any, error) {
	return d.String(), nil
}

func (d *DNSUrl) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}

	text = strings.ToLower(text)
	network := "udp"
	if before, after, found := strings.Cut(text, "://"); found {
		network = before
		text = after
	}

	if network != "udp" && network != "tcp" {
		return errors.New("invalid dns url schema")
	}

	ap := &DNSAddrPort{}
	if err := ap.UnmarshalText([]byte(text)); err != nil {
		return err
	}

	*d = DNSUrl{Network: network, AddrPort: *ap}

	return nil
}

func (d DNSUrl) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d DNSUrl) String() string {
	return fmt.Sprintf("%s://%s", d.Network, d.AddrPort)
}
