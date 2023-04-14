package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"

	"github.com/Dreamacro/clash/adapter/outbound"
	C "github.com/Dreamacro/clash/constant"
)

func TestWireGuard(t *testing.T) {
	configPath := C.Path.Resolve("wireguard.conf")

	cfg := &container.Config{
		Image: ImageBoringTun,
		ExposedPorts: nat.PortSet{
			"10002/tcp": struct{}{},
			"10002/udp": struct{}{},
			"10001/tcp": struct{}{},
			"10001/udp": struct{}{},
		},
		Cmd: []string{"wg0"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: nat.PortMap{
			"10002/tcp": []nat.PortBinding{
				{HostPort: "10002", HostIP: "0.0.0.0"},
			},
			"10002/udp": []nat.PortBinding{
				{HostPort: "10002", HostIP: "0.0.0.0"},
			},
			"10001/tcp": []nat.PortBinding{
				{HostPort: "10001", HostIP: "0.0.0.0"},
			},
			"10001/udp": []nat.PortBinding{
				{HostPort: "10001", HostIP: "0.0.0.0"},
			},
		},
		Binds:  []string{fmt.Sprintf("%s:/etc/wireguard/wg0.conf", configPath)},
		CapAdd: []string{"MKNOD", "NET_ADMIN", "NET_RAW"},
	}

	id, err := startContainer(cfg, hostCfg, "wireguard")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = cleanContainer(id)
	})

	time.Sleep(10 * time.Second)

	proxy, err := outbound.NewWireGuard(outbound.WireGuardOption{
		Name:       "wireguard",
		Server:     "127.0.0.1",
		Port:       10002,
		IP:         "10.0.0.2",
		PrivateKey: "YKROUG06L42T55xJdOXIVigxy1NsRx5SBz9i9qHQ2n8=",
		PublicKey:  "faV63mM7pkfFWFWO+nBpoxNy7JMvhawhMaEpadNr2lI=",
		UDP:        true,
	})
	require.NoError(t, err)

	testSuit(t, proxy)
}
