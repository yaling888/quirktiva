package constant

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Listener interface {
	RawAddress() string
	Address() string
	Close() error
}

type InboundType string

const (
	InboundTypeSocks  InboundType = "socks"
	InboundTypeSocks4 InboundType = "socks4"
	InboundTypeSocks5 InboundType = "socks5"
	InboundTypeRedir  InboundType = "redir"
	InboundTypeTproxy InboundType = "tproxy"
	InboundTypeHTTP   InboundType = "http"
	InboundTypeMixed  InboundType = "mixed"
	InboundTypeMitm   InboundType = "mitm"
)

var supportInboundTypes = map[InboundType]bool{
	InboundTypeSocks:  true,
	InboundTypeSocks4: true,
	InboundTypeSocks5: true,
	InboundTypeRedir:  true,
	InboundTypeTproxy: true,
	InboundTypeHTTP:   true,
	InboundTypeMixed:  true,
	InboundTypeMitm:   true,
}

type inbound struct {
	Type          InboundType `json:"type" yaml:"type"`
	BindAddress   string      `json:"bind-address" yaml:"bind-address"`
	IsFromPortCfg bool        `json:"-" yaml:"-"`
}

type Inbound inbound

// UnmarshalYAML implements yaml.Unmarshaler
func (i *Inbound) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	if err := unmarshal(&tp); err != nil {
		var inner inbound
		if err := unmarshal(&inner); err != nil {
			return err
		}
		*i = Inbound(inner)
	} else {
		inner, err := parseInbound(tp)
		if err != nil {
			return err
		}
		*i = Inbound(*inner)
	}

	typeStr := strings.ToLower(string(i.Type))
	switch typeStr {
	case "https":
		i.Type = InboundTypeHTTP
	case "socks4a":
		i.Type = InboundTypeSocks4
	case "socks5h":
		i.Type = InboundTypeSocks5
	default:
		i.Type = InboundType(typeStr)
	}

	if !supportInboundTypes[i.Type] {
		return fmt.Errorf("not support inbound type: %s", i.Type)
	}
	_, portStr, err := net.SplitHostPort(i.BindAddress)
	if err != nil {
		return fmt.Errorf("bind address parse error, addr: %s, error: %v", i.ToAlias(), err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("invalid bind port, addr: %s", i.ToAlias())
	}
	return nil
}

func parseInbound(alias string) (*inbound, error) {
	u, err := url.Parse(alias)
	if err != nil {
		return nil, err
	}
	listenerType := InboundType(u.Scheme)
	return &inbound{
		Type:        listenerType,
		BindAddress: u.Host,
	}, nil
}

func (i *Inbound) ToAlias() string {
	return string(i.Type) + "://" + i.BindAddress
}
