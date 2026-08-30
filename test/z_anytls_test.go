package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/require"

	"github.com/yaling888/quirktiva/adapter/outbound"
	C "github.com/yaling888/quirktiva/constant"
)

func TestClash_AnyTLS(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageSingBox,
		ExposedPorts: defaultExposedPorts,
		Cmd:          []string{"-D", "/var/lib/sing-box", "-C", "/etc/sing-box/", "run"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/sing-box/config.json", C.Path.Resolve("anytls.json")),
			fmt.Sprintf("%s:/etc/sing-box/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/etc/sing-box/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "anytls")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = cleanContainer(id)
	})

	proxy, err := outbound.NewAnyTLS(outbound.AnyTLSOption{
		Name:           "anytls",
		Server:         localIP.String(),
		Port:           10002,
		Password:       "b831381d-6324-4d53-ad4f-8cda48b30811",
		SNI:            "example.org",
		UDP:            true,
		SkipCertVerify: true,
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}

func TestClash_AnyTLS_uTLS(t *testing.T) {
	cfg := &container.Config{
		Image:        ImageSingBox,
		ExposedPorts: defaultExposedPorts,
		Cmd:          []string{"-D", "/var/lib/sing-box", "-C", "/etc/sing-box/", "run"},
	}
	hostCfg := &container.HostConfig{
		PortBindings: defaultPortBindings,
		Binds: []string{
			fmt.Sprintf("%s:/etc/sing-box/config.json", C.Path.Resolve("anytls.json")),
			fmt.Sprintf("%s:/etc/sing-box/fullchain.pem", C.Path.Resolve("example.org.pem")),
			fmt.Sprintf("%s:/etc/sing-box/privkey.pem", C.Path.Resolve("example.org-key.pem")),
		},
	}

	id, err := startContainer(cfg, hostCfg, "anytls-utls")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = cleanContainer(id)
	})

	proxy, err := outbound.NewAnyTLS(outbound.AnyTLSOption{
		Name:              "anytls",
		Server:            localIP.String(),
		Port:              10002,
		Password:          "b831381d-6324-4d53-ad4f-8cda48b30811",
		SNI:               "example.org",
		UDP:               true,
		SkipCertVerify:    true,
		ClientFingerprint: "chrome",
	})
	require.NoError(t, err)

	time.Sleep(waitTime)
	testSuit(t, proxy)
}
