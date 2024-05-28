package main

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/listener"
	"github.com/yaling888/quirktiva/tunnel"
)

func TestClash_Listener(t *testing.T) {
	basic := `
log-level: silent
port: 8890
socks-port: 8891
mixed-port: 8892
mitm-port: 8893
`

	err := parseAndApply(basic)
	require.NoError(t, err)
	defer cleanup()

	time.Sleep(waitTime)

	for i := 8890; i <= 8893; i++ {
		require.True(t, TCPing(net.JoinHostPort("127.0.0.1", strconv.Itoa(i))), "tcp port %d", i)
	}
}

func TestClash_ListenerCreate(t *testing.T) {
	basic := `
log-level: silent
`
	err := parseAndApply(basic)
	require.NoError(t, err)
	defer cleanup()

	time.Sleep(waitTime)
	tcpIn := tunnel.TCPIn()
	udpIn := tunnel.UDPIn()

	ports := listener.Ports{
		Port: 8890,
	}
	listener.ReCreatePortsListeners(ports, tcpIn, udpIn)
	require.True(t, TCPing("127.0.0.1:8890"))
	require.Equal(t, ports, *listener.GetPorts())

	inbounds := []C.Inbound{
		{
			Type:        C.InboundTypeHTTP,
			BindAddress: "127.0.0.1:8891",
		},
	}
	listener.ReCreateListeners(inbounds, tcpIn, udpIn)
	require.True(t, TCPing("127.0.0.1:8890"))
	require.Equal(t, ports, *listener.GetPorts())

	require.True(t, TCPing("127.0.0.1:8891"))
	require.Equal(t, len(inbounds), len(listener.GetInbounds()))

	ports.Port = 0
	ports.SocksPort = 8892
	listener.ReCreatePortsListeners(ports, tcpIn, udpIn)
	require.False(t, TCPing("127.0.0.1:8890"))
	require.True(t, TCPing("127.0.0.1:8892"))
	require.Equal(t, ports, *listener.GetPorts())

	require.True(t, TCPing("127.0.0.1:8891"))
	require.Equal(t, len(inbounds), len(listener.GetInbounds()))
}
