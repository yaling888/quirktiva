package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClash_RuleInbound(t *testing.T) {
	basic := `
socks-port: 8890
inbounds:
  - socks://127.0.0.1:8891
  - type: socks
    bind-address: 127.0.0.1:8892
rules:
  - INBOUND-PORT,8891,REJECT
  - MATCH,DIRECT
log-level: silent
`

	err := parseAndApply(basic)
	require.NoError(t, err)
	defer cleanup()

	require.True(t, TCPing(net.JoinHostPort("127.0.0.1", "8890")))
	require.True(t, TCPing(net.JoinHostPort("127.0.0.1", "8891")))
	require.True(t, TCPing(net.JoinHostPort("127.0.0.1", "8892")))

	require.Error(t, testPingPongWithSocksPort(t, 8891))
	require.NoError(t, testPingPongWithSocksPort(t, 8890))
	require.NoError(t, testPingPongWithSocksPort(t, 8892))
}
