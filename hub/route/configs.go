package route

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/phuslu/log"
	"github.com/samber/lo"

	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/hub/executor"
	"github.com/Dreamacro/clash/listener"
	L "github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"
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
		Tun         *struct {
			Enable              *bool       `json:"enable,omitempty"`
			Device              *string     `json:"device,omitempty"`
			Stack               *C.TUNStack `json:"stack,omitempty"`
			DNSHijack           *[]C.DNSUrl `json:"dns-hijack,omitempty"`
			AutoRoute           *bool       `json:"auto-route,omitempty"`
			AutoDetectInterface *bool       `json:"auto-detect-interface,omitempty"`
		}
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
		resolver.DisableIPv6 = !*general.IPv6
	}

	if general.Sniffing != nil {
		tunnel.SetSniffing(*general.Sniffing)
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
		tunConf := listener.GetTunConf()
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

	force := r.URL.Query().Get("force") == "true"
	var cfg *config.Config
	var err error

	if req.Payload != "" {
		log.Warn().Msg("[API] update config by payload")
		cfg, err = executor.ParseWithBytes([]byte(req.Payload))
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	} else {
		if req.Path == "" {
			req.Path = C.Path.Config()
		}
		if !filepath.IsAbs(req.Path) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("path is not a absolute path"))
			return
		}

		log.Warn().Str("file", req.Path).Msg("[API] reload config")
		cfg, err = executor.ParseWithPath(req.Path)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	}

	executor.ApplyConfig(cfg, force)
	render.NoContent(w, r)
}
