package constant

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/samber/lo"

	"github.com/yaling888/quirktiva/component/auth"
)

type Listener interface {
	RawAddress() string
	Address() string
	Close() error
}

type AuthenticatorListener interface {
	SetAuthenticator([]auth.AuthUser)
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
	Type           InboundType `json:"type" yaml:"type"`
	BindAddress    string      `json:"bind-address" yaml:"bind-address"`
	Authentication *[]string   `json:"authentication" yaml:"authentication"`
	IsFromPortCfg  bool        `json:"-" yaml:"-"`
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
	return verifyInbound(i)
}

// UnmarshalJSON implements encoding/json.Unmarshaler
func (i *Inbound) UnmarshalJSON(data []byte) error {
	var tp string
	if err := json.Unmarshal(data, &tp); err != nil {
		var inner inbound
		if err := json.Unmarshal(data, &inner); err != nil {
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
	return verifyInbound(i)
}

// MarshalJSON implements encoding/json.Marshaler
func (i *Inbound) MarshalJSON() ([]byte, error) {
	auLen := len(lo.FromPtr(i.Authentication))
	auths := make([]string, 0, auLen)
	if auLen != 0 {
		auths = lo.Map(*i.Authentication, func(au string, _ int) string {
			ss := strings.Split(au, ":")
			s := ss[0]
			l := len(s)
			if l == 0 {
				return ""
			}
			return fmt.Sprintf("%s****%s", s[0:1], s[l-1:l])
		})
	}
	return json.Marshal(map[string]any{
		"type":           string(i.Type),
		"bind-address":   i.BindAddress,
		"authentication": auths,
	})
}

func (i *Inbound) Key() string {
	if i == nil {
		return ""
	}
	return fmt.Sprintf("%s:%s:%v", i.Type, i.BindAddress, i.IsFromPortCfg)
}

func (i *Inbound) ToAlias() string {
	if i == nil {
		return "<nil>"
	}
	return string(i.Type) + "://" + i.BindAddress
}

func parseInbound(alias string) (*inbound, error) {
	u, err := url.Parse(alias)
	if err != nil {
		return nil, err
	}
	listenerType := InboundType(u.Scheme)
	i := &inbound{
		Type:        listenerType,
		BindAddress: u.Host,
	}
	if u.User != nil {
		au := u.User.String()
		if !strings.Contains(au, ":") {
			au += ":"
		}
		i.Authentication = &[]string{au}
	}
	return i, nil
}

func verifyInbound(i *Inbound) error {
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
		return fmt.Errorf("parse inbound bind address error, address: %s, error: %w", i.ToAlias(), err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("invalid inbound bind port, address: %s", i.ToAlias())
	}
	if i.Authentication != nil && lo.SomeBy(*i.Authentication, func(s string) bool {
		return !strings.Contains(s, ":")
	}) {
		return fmt.Errorf("invalid inbound authentication, address: %s", i.ToAlias())
	}
	return nil
}

var proxyInbound *Inbound

// SetProxyInbound assigns a http or socks inbound to proxyInbound
func SetProxyInbound(tcpInbounds map[string]Inbound) {
	tcpIns := tcpInbounds
	for _, tcp := range tcpIns {
		switch tcp.Type {
		case InboundTypeHTTP, InboundTypeSocks, InboundTypeSocks5, InboundTypeMixed:
			proxyInbound = &tcp
			return
		}
	}
	proxyInbound = nil
}

// ProxyURL returns a proxy function (for use in a http.Transport),
// nil if no inbound ports are set
func ProxyURL(auth auth.Authenticator) func(*http.Request) (*url.URL, error) {
	mInbound := proxyInbound
	if mInbound == nil {
		return nil
	}

	var schema string
	switch mInbound.Type {
	case InboundTypeHTTP:
		schema = "http"
	case InboundTypeSocks, InboundTypeSocks5, InboundTypeMixed:
		schema = "socks5"
	default:
		return nil
	}

	var userInfo *url.Userinfo
	if auths := mInbound.Authentication; len(lo.FromPtr(auths)) != 0 {
		user := strings.Split((*auths)[0], ":")
		userInfo = url.UserPassword(user[0], user[1])
	} else if auth != nil {
		if user := auth.RandomUser(); user != nil {
			userInfo = url.UserPassword(user.User, user.Pass)
		}
	}

	fixedURL := &url.URL{
		Scheme: schema,
		User:   userInfo,
		Host:   mInbound.BindAddress,
	}
	return http.ProxyURL(fixedURL)
}
