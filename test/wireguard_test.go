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
	configPath := C.Path.Resolve("wireguard.conf")

	cfg := &container.Config{
		Image:        ImageBoringTun,
		ExposedPorts: defaultExposedPorts,
		Cmd:          []string{"wg0"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds:        []string{fmt.Sprintf("%s:/etc/wireguard/wg0.conf", configPath)},
		CapAdd:       []string{"MKNOD", "NET_ADMIN", "NET_RAW"},
	}

	id, err := startContainer(cfg, hostCfg, "wireguard")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = cleanContainer(id)
	})

	proxy, err := outbound.NewWireGuard(outbound.WireGuardOption{
		Name:       "wireguard",
		Server:     localIP.String(),
		Port:       10002,
		IP:         "10.0.0.2",
		PrivateKey: "YKROUG06L42T55xJdOXIVigxy1NsRx5SBz9i9qHQ2n8=",
		PublicKey:  "faV63mM7pkfFWFWO+nBpoxNy7JMvhawhMaEpadNr2lI=",
		UDP:        true,
	})
	require.NoError(t, err)

	time.Sleep(5 * time.Second)
	testSuit(t, proxy)
}
