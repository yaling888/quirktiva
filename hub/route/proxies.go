package route

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"

	"github.com/yaling888/quirktiva/adapter"
	"github.com/yaling888/quirktiva/adapter/outboundgroup"
	"github.com/yaling888/quirktiva/component/profile/cachefile"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/tunnel"
)

func proxyRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies)

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName)
		r.Get("/", getProxy)
		r.Get("/delay", getProxyDelay)
		r.Put("/", updateProxy)
	})
	return r
}

func parseProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProxyByName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Context().Value(CtxKeyProxyName).(string)
		proxy, exist := tunnel.FindProxyByName(name)

		if !exist {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getProxies(w http.ResponseWriter, r *http.Request) {
	proxies := tunnel.Proxies()
	render.JSON(w, r, render.M{
		"proxies": proxies,
	})
}

func getProxy(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	render.JSON(w, r, proxy)
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Name string `json:"name"`
	}{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(*adapter.Proxy)
	selector, ok := proxy.ProxyAdapter.(*outboundgroup.Selector)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Selector"))
		return
	}

	if err := selector.Set(req.Name); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(fmt.Sprintf("Selector update error: %s", err.Error())))
		return
	}

	cachefile.Cache().SetSelected(proxy.Name(), req.Name)
	render.NoContent(w, r)
}

func getProxyDelay(w http.ResponseWriter, r *http.Request) {
	var (
		query      = r.URL.Query()
		url        = query.Get("url")
		timeoutStr = query.Get("timeout")
		timeout    time.Duration
	)

	t, err := strconv.ParseInt(timeoutStr, 10, 64)
	if err != nil {
		d, err := time.ParseDuration(timeoutStr)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, ErrBadRequest)
			return
		}
		timeout = d
	} else {
		timeout = time.Duration(t) * time.Millisecond
	}

	if timeout < time.Millisecond || timeout > 30*time.Second {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(fmt.Sprintf("invalid timeout, got %s, want 1ms to 30s", timeout)))
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	delay, avgDelay, err := proxy.URLTest(ctx, url)
	if ctx.Err() != nil {
		render.Status(r, http.StatusGatewayTimeout)
		render.JSON(w, r, ErrRequestTimeout)
		return
	}

	if err != nil || delay == 0 {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError("An error occurred in the delay test"))
		return
	}

	render.JSON(w, r, render.M{
		"delay":     delay,
		"meanDelay": avgDelay,
	})
}
