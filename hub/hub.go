package hub

import (
	"github.com/yaling888/quirktiva/config"
	"github.com/yaling888/quirktiva/hub/executor"
	"github.com/yaling888/quirktiva/hub/route"
)

type Option func(*config.Config)

func WithExternalUI(externalUI string) Option {
	return func(cfg *config.Config) {
		cfg.General.ExternalUI = externalUI
	}
}

func WithExternalController(externalController string) Option {
	return func(cfg *config.Config) {
		cfg.General.ExternalController = externalController
	}
}

func WithExternalServerName(externalServerName string) Option {
	return func(cfg *config.Config) {
		cfg.General.ExternalServerName = externalServerName
	}
}

func WithSecret(secret string) Option {
	return func(cfg *config.Config) {
		cfg.General.Secret = secret
	}
}

// Parse call at the beginning of clash
func Parse(options ...Option) error {
	cfg, err := executor.Parse()
	if err != nil {
		return err
	}

	for _, option := range options {
		option(cfg)
	}

	if cfg.General.ExternalUI != "" {
		route.SetUIPath(cfg.General.ExternalUI)
	}

	if cfg.General.ExternalServerName != "" {
		route.SetServerName(cfg.General.ExternalServerName)
	}

	route.SetPPROF(cfg.General.PPROF)

	if cfg.General.ExternalController != "" {
		go route.Start(cfg.General.ExternalController, cfg.General.Secret)
	}

	executor.ApplyConfig(cfg, true)
	return nil
}
