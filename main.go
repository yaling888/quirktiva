package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	_ "time/tzdata"

	"github.com/phuslu/log"
	"go.uber.org/automaxprocs/maxprocs"

	"github.com/yaling888/clash/config"
	C "github.com/yaling888/clash/constant"
	"github.com/yaling888/clash/hub"
	"github.com/yaling888/clash/hub/executor"
	cLog "github.com/yaling888/clash/log"
)

var (
	version            bool
	testConfig         bool
	homeDir            string
	configFile         string
	externalUI         string
	externalController string
	secret             string
)

func init() {
	flag.StringVar(&homeDir, "d", os.Getenv("CLASH_HOME_DIR"), "set configuration directory")
	flag.StringVar(&configFile, "f", os.Getenv("CLASH_CONFIG_FILE"), "specify configuration file")
	flag.StringVar(&externalUI, "ext-ui", os.Getenv("CLASH_OVERRIDE_EXTERNAL_UI_DIR"),
		"override external ui directory")
	flag.StringVar(&externalController, "ext-ctl", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER"),
		"override external controller address")
	flag.StringVar(&secret, "secret", os.Getenv("CLASH_OVERRIDE_SECRET"),
		"override secret for RESTful API")
	flag.BoolVar(&version, "v", false, "show current version of clash")
	flag.BoolVar(&testConfig, "t", false, "test configuration and exit")
	flag.Parse()
}

func main() {
	_, _ = maxprocs.Set(maxprocs.Logger(func(string, ...any) {}))
	if version {
		fmt.Printf("Clash Plus Pro %s %s %s with %s %s\n",
			C.Version,
			runtime.GOOS,
			runtime.GOARCH,
			runtime.Version(),
			C.BuildTime,
		)
		return
	}

	if homeDir != "" {
		if !filepath.IsAbs(homeDir) {
			currentDir, _ := os.Getwd()
			homeDir = filepath.Join(currentDir, homeDir)
		}
		C.SetHomeDir(homeDir)
	}

	if configFile != "" {
		if !filepath.IsAbs(configFile) {
			currentDir, _ := os.Getwd()
			configFile = filepath.Join(currentDir, configFile)
		}
		C.SetConfig(configFile)
	} else {
		configFile = filepath.Join(C.Path.HomeDir(), C.Path.Config())
		C.SetConfig(configFile)
	}

	if err := config.Init(C.Path.HomeDir()); err != nil {
		log.Fatal().
			Err(err).
			Str("dir", C.Path.HomeDir()).
			Str("path", C.Path.Config()).
			Msg("[Config] initial configuration failed")
	}

	if testConfig {
		if _, err := executor.Parse(); err != nil {
			log.Fatal().
				Err(err).
				Str("path", C.Path.Config()).
				Msg("[Config] configuration file test failed")
		}
		log.Info().
			Str("path", C.Path.Config()).
			Msg("[Config] configuration file test is successful")
		return
	}

	var options []hub.Option
	if externalUI != "" {
		options = append(options, hub.WithExternalUI(externalUI))
	}
	if externalController != "" {
		options = append(options, hub.WithExternalController(externalController))
	}
	if secret != "" {
		options = append(options, hub.WithSecret(secret))
	}

	if err := hub.Parse(options...); err != nil {
		log.Fatal().
			Err(err).
			Str("path", C.Path.Config()).
			Msg("[Config] parse config failed")
	}

	oldLevel := cLog.Level()
	cLog.SetLevel(cLog.INFO)
	log.Info().
		Str("version", fmt.Sprintf("%s %s %s with %s %s",
			C.Version,
			runtime.GOOS,
			runtime.GOARCH,
			runtime.Version(),
			C.BuildTime,
		)).
		Msg("[Main] Clash Plus started")
	cLog.SetLevel(oldLevel)

	defer executor.Shutdown()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		s := <-sigCh
		switch s {
		case syscall.SIGHUP:
			level := cLog.Level()
			cLog.SetLevel(cLog.INFO)

			log.Info().Str("path", C.Path.Config()).Msg("[Main] configuration file reloading...")

			if conf, err := executor.Parse(); err == nil {
				executor.ApplyConfig(conf, true)

				level = cLog.Level()
				cLog.SetLevel(cLog.INFO)

				log.Info().Str("path", C.Path.Config()).Msg("[Main] configuration file reloaded")
			} else {
				log.Error().
					Err(err).
					Str("path", C.Path.Config()).
					Msg("[Main] reload config failed")
			}
			cLog.SetLevel(level)
		default:
			return
		}
	}
}
