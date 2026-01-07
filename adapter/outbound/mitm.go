package outbound

import (
	"context"
	"net"

	"github.com/yaling888/quirktiva/component/auth"
	"github.com/yaling888/quirktiva/component/dialer"
	C "github.com/yaling888/quirktiva/constant"
)

var _ C.ProxyAdapter = (*Mitm)(nil)

type Mitm struct {
	*Base
	serverAddr      *net.TCPAddr
	httpProxyClient *Http
}

// DialContext implements C.ProxyAdapter
func (m *Mitm) DialContext(_ context.Context, metadata *C.Metadata, _ ...dialer.Option) (C.Conn, error) {
	c, err := net.DialTCP("tcp", nil, m.serverAddr)
	if err != nil {
		return nil, err
	}

	_ = c.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true})

	metadata.Type = C.MITM

	hc, err := m.httpProxyClient.StreamConn(c, metadata)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	return NewConn(hc, m), nil
}

func NewMitm(serverAddr string, auths auth.Authenticator) *Mitm {
	var (
		option     = HttpOption{}
		tcpAddr, _ = net.ResolveTCPAddr("tcp", serverAddr)
	)
	if auths != nil {
		if user := auths.RandomUser(); user != nil {
			option.UserName = user.User
			option.Password = user.Pass
		}
	}
	cl, err := NewHttp(option)
	if err != nil {
		panic("unreachable")
	}
	return &Mitm{
		Base: &Base{
			name: "Mitm",
			tp:   C.Mitm,
		},
		serverAddr:      tcpAddr,
		httpProxyClient: cl,
	}
}
