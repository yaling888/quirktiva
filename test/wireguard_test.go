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
			"10002/udp": struct{}{},
		},
		Cmd: []string{"wg0"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: nat.PortMap{
			"10002/udp": []nat.PortBinding{
				{HostPort: "10002", HostIP: "0.0.0.0"},
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

	proxy, err := outbound.NewWireGuard(outbound.WireGuardOption{
		Name:       "wireguard",
		Server:     localIP.String(),
		Port:       10002,
		IP:         "10.0.0.2",
		PrivateKey: "eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=",
		PublicKey:  "Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=",
		UDP:        true,
	})
	require.NoError(t, err)

	time.Sleep(5 * time.Second)
	testSuit(t, proxy)
}
