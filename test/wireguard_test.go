package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/require"

	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"
)

func TestWireGuard(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageWireguardGo,
		ExposedPorts: defaultExposedPorts,
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds:        []string{fmt.Sprintf("%s:/etc/wireguard/wg0.conf", C.Path.Resolve("wireguard.conf"))},
		CapAdd:       []string{"MKNOD", "NET_ADMIN", "NET_RAW"},
	}

	id, err := startContainer(cfg, hostCfg, "wireguard")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = cleanContainer(id)
	})

	proxy, err := outbound.NewWireGuard(outbound.WireGuardOption{
		Name:       "wireguard",
		Server:     "127.0.0.1",
		Port:       10002,
		IP:         "10.0.0.2",
		PrivateKey: "YKROUG06L42T55xJdOXIVigxy1NsRx5SBz9i9qHQ2n8=",
		PublicKey:  "faV63mM7pkfFWFWO+nBpoxNy7JMvhawhMaEpadNr2lI=",
		UDP:        false,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)

	testSuit(t, proxy)
}
