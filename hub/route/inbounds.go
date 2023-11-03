package route

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	C "github.com/yaling888/clash/constant"
	"github.com/yaling888/clash/listener"
	"github.com/yaling888/clash/tunnel"
)

func inboundRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getInbounds)
	r.Put("/", updateInbounds)
	return r
}

func getInbounds(w http.ResponseWriter, r *http.Request) {
	inbounds := listener.GetInbounds()
	render.JSON(w, r, render.M{
		"inbounds": inbounds,
	})
}

func updateInbounds(w http.ResponseWriter, r *http.Request) {
	var req []C.Inbound
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	tcpIn := tunnel.TCPIn()
	udpIn := tunnel.UDPIn()
	listener.ReCreateListeners(req, tcpIn, udpIn)
	render.NoContent(w, r)
}
