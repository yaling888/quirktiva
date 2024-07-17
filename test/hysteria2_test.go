package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/require"

	"github.com/yaling888/quirktiva/adapter/outbound"
	C "github.com/yaling888/quirktiva/constant"
)

func TestClash_Hysteria2(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageHysteria2,
		ExposedPorts: defaultExposedPorts,
		Entrypoint:   []string{"hysteria"},
		Cmd:          []string{"server", "-c", "/app/config.yaml"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/app/config.yaml", C.Path.Resolve("hysteria2.yaml")),
			fmt.Sprintf("%s:/app/fullchain.crt", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/app/privkey.key", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "hysteria2")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = cleanContainer(id)
	})

	proxy, err := outbound.NewHysteria2(outbound.Hysteria2Option{
		Name:           "hysteria2",
		Server:         localIP.String(),
		Port:           10002,
		Password:       "password",
		SNI:            "example.org",
		PinSHA256:      "8A:8A:D4:06:6D:4A:92:7D:3D:12:03:D1:10:AC:F5:20:35:9A:5D:F3:CB:77:0B:DD:03:79:1C:B4:7D:F1:3D:C8",
		SkipCertVerify: true,
		UDP:            true,
		Up:             "100 mbps",
		Down:           "1000 mbps",
	})
	require.NoError(t, err)

	time.Sleep(waitTime)

	testSuit(t, proxy)
}

func TestClash_Hysteria2Obfs(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageHysteria2,
		ExposedPorts: defaultExposedPorts,
		Entrypoint:   []string{"hysteria"},
		Cmd:          []string{"server", "-c", "/app/config.yaml"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/app/config.yaml", C.Path.Resolve("hysteria2-obfs.yaml")),
			fmt.Sprintf("%s:/app/fullchain.crt", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/app/privkey.key", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "hysteria2-obfs")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = cleanContainer(id)
	})

	proxy, err := outbound.NewHysteria2(outbound.Hysteria2Option{
		Name:           "hysteria2",
		Server:         localIP.String(),
		Port:           10002,
		Password:       "password",
		SNI:            "example.org",
		Fingerprint:    "8A:8A:D4:06:6D:4A:92:7D:3D:12:03:D1:10:AC:F5:20:35:9A:5D:F3:CB:77:0B:DD:03:79:1C:B4:7D:F1:3D:C8",
		SkipCertVerify: true,
		UDP:            true,
		Up:             "100 mbps",
		Down:           "1000 mbps",
		Obfs:           "salamander",
		ObfsParam:      "password",
	})
	require.NoError(t, err)

	time.Sleep(waitTime)

	testSuit(t, proxy)
}

func TestClash_Hysteria2Hop(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageHysteria2,
		ExposedPorts: defaultExposedPorts,
		Entrypoint:   []string{"hysteria"},
		Cmd:          []string{"server", "-c", "/app/config.yaml"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/app/config.yaml", C.Path.Resolve("hysteria2-hop.yaml")),
			fmt.Sprintf("%s:/app/fullchain.crt", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/app/privkey.key", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "hysteria2-hop")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = cleanContainer(id)
	})

	proxy, err := outbound.NewHysteria2(outbound.Hysteria2Option{
		Name:           "hysteria2",
		Server:         localIP.String(),
		Ports:          "10002-10002",
		Password:       "password",
		SNI:            "example.org",
		Fingerprint:    "8A:8A:D4:06:6D:4A:92:7D:3D:12:03:D1:10:AC:F5:20:35:9A:5D:F3:CB:77:0B:DD:03:79:1C:B4:7D:F1:3D:C8",
		SkipCertVerify: true,
		UDP:            true,
		Up:             "100 mbps",
		Down:           "1000 mbps",
	})
	require.NoError(t, err)

	time.Sleep(waitTime)

	testSuit(t, proxy)
}
