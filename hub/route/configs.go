package route

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/phuslu/log"
	"github.com/samber/lo"

	"github.com/yaling888/quirktiva/component/resolver"
	"github.com/yaling888/quirktiva/config"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/hub/executor"
	"github.com/yaling888/quirktiva/listener"
	L "github.com/yaling888/quirktiva/log"
	"github.com/yaling888/quirktiva/tunnel"
)

func configRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConfigs)
	r.Put("/", updateConfigs)
	r.Patch("/", patchConfigs)
	return r
}

func getConfigs(w http.ResponseWriter, r *http.Request) {
	general := executor.GetGeneral()
	render.JSON(w, r, general)
}

func patchConfigs(w http.ResponseWriter, r *http.Request) {
	type tun struct {
		Enable              *bool       `json:"enable,omitempty"`
		Device              *string     `json:"device,omitempty"`
		Stack               *C.TUNStack `json:"stack,omitempty"`
		DNSHijack           *[]C.DNSUrl `json:"dns-hijack,omitempty"`
		AutoRoute           *bool       `json:"auto-route,omitempty"`
		AutoDetectInterface *bool       `json:"auto-detect-interface,omitempty"`
	}
	general := struct {
		Port        *int               `json:"port,omitempty"`
		SocksPort   *int               `json:"socks-port,omitempty"`
		RedirPort   *int               `json:"redir-port,omitempty"`
		TProxyPort  *int               `json:"tproxy-port,omitempty"`
		MixedPort   *int               `json:"mixed-port,omitempty"`
		MitmPort    *int               `json:"mitm-port,omitempty"`
		AllowLan    *bool              `json:"allow-lan,omitempty"`
		BindAddress *string            `json:"bind-address,omitempty"`
		Mode        *tunnel.TunnelMode `json:"mode,omitempty"`
		LogLevel    *L.LogLevel        `json:"log-level,omitempty"`
		IPv6        *bool              `json:"ipv6,omitempty"`
		Sniffing    *bool              `json:"sniffing,omitempty"`
		Tun         *tun               `json:"tun,omitempty"`
	}{}

	if err := render.DecodeJSON(r.Body, &general); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	if general.AllowLan != nil {
		listener.SetAllowLan(*general.AllowLan)
	}

	if general.BindAddress != nil {
		listener.SetBindAddress(*general.BindAddress)
	}

	if general.Mode != nil {
		tunnel.SetMode(*general.Mode)
	}

	if general.LogLevel != nil {
		L.SetLevel(*general.LogLevel)
	}

	if general.IPv6 != nil {
		resolver.SetDisableIPv6(!*general.IPv6)
	}

	if general.Sniffing != nil {
		tunnel.SetSniffing(*general.Sniffing || resolver.SniffingEnabled())
	}

	tcpIn := tunnel.TCPIn()
	udpIn := tunnel.UDPIn()

	ports := listener.GetPorts()
	ports.Port = lo.FromPtrOr(general.Port, ports.Port)
	ports.SocksPort = lo.FromPtrOr(general.SocksPort, ports.SocksPort)
	ports.RedirPort = lo.FromPtrOr(general.RedirPort, ports.RedirPort)
	ports.TProxyPort = lo.FromPtrOr(general.TProxyPort, ports.TProxyPort)
	ports.MixedPort = lo.FromPtrOr(general.MixedPort, ports.MixedPort)
	ports.MitmPort = lo.FromPtrOr(general.MitmPort, ports.MitmPort)

	listener.ReCreatePortsListeners(*ports, tcpIn, udpIn)

	if general.Tun != nil {
		tunSchema := general.Tun
		tunConf := C.GetTunConf()
		tunConf.StopRouteListener = true

		tunConf.Enable = lo.FromPtrOr(tunSchema.Enable, tunConf.Enable)
		tunConf.Device = lo.FromPtrOr(tunSchema.Device, tunConf.Device)
		tunConf.Stack = lo.FromPtrOr(tunSchema.Stack, tunConf.Stack)
		tunConf.DNSHijack = lo.FromPtrOr(tunSchema.DNSHijack, tunConf.DNSHijack)
		tunConf.AutoRoute = lo.FromPtrOr(tunSchema.AutoRoute, tunConf.AutoRoute)
		tunConf.AutoDetectInterface = lo.FromPtrOr(tunSchema.AutoDetectInterface, tunConf.AutoDetectInterface)

		listener.ReCreateTun(&tunConf, tcpIn, udpIn)
		listener.ReCreateRedirToTun(tunConf.RedirectToTun)
	}

	msg, _ := json.Marshal(general)
	log.Warn().Str("data", string(msg)).Msg("[API] patch config")

	render.NoContent(w, r)
}

func updateConfigs(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Path    string `json:"path"`
		Payload string `json:"payload"`
	}{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	var (
		cfg      *config.Config
		err      error
		hasPath  bool
		oldLevel = L.Level()
		force    = r.URL.Query().Get("force") == "true"
	)

	defer func() {
		if err == nil {
			oldLevel = L.Level()
			L.SetLevel(L.INFO)
			if req.Payload != "" {
				log.Info().Msg("[API] payload config updated")
			} else {
				if hasPath {
					C.SetConfig(req.Path)
				}
				log.Info().Str("path", req.Path).Msg("[API] configuration file reloaded")
			}
		}
		L.SetLevel(oldLevel)
	}()

	L.SetLevel(L.INFO)

	if req.Payload != "" {
		log.Info().Msg("[API] payload config updating...")

		cfg, err = executor.ParseWithBytes([]byte(req.Payload))
		if err != nil {
			log.Error().Err(err).Msg("[API] update config failed")

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	} else {
		if hasPath = req.Path != ""; !hasPath {
			req.Path = C.Path.Config()
		}

		log.Info().Str("path", req.Path).Msg("[API] configuration file reloading...")

		if !filepath.IsAbs(req.Path) {
			err = errors.New("path is not a absolute path")
			log.Error().
				Err(err).
				Str("path", req.Path).
				Msg("[API] reload config failed")

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}

		cfg, err = executor.ParseWithPath(req.Path)
		if err != nil {
			log.Error().
				Err(err).
				Str("path", req.Path).
				Msg("[API] reload config failed")

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	}

	executor.ApplyConfig(cfg, force)
	render.NoContent(w, r)
}
