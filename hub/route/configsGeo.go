package route

import (
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/config"
	"github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/hub/executor"
	L "github.com/yaling888/quirktiva/log"
)

var (
	updatingGeo  bool
	updateGeoMux sync.Mutex
)

func configGeoRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/", updateGeoDatabases)
	return r
}

func updateGeoDatabases(w http.ResponseWriter, r *http.Request) {
	updateGeoMux.Lock()

	if updatingGeo {
		updateGeoMux.Unlock()
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("updating..."))
		return
	}

	updatingGeo = true
	updateGeoMux.Unlock()

	go func() {
		var (
			cfg      *config.Config
			err      error
			oldLevel = L.Level()
		)

		defer func() {
			if err == nil {
				oldLevel = L.Level()
				L.SetLevel(L.INFO)
				log.Info().Str("path", constant.Path.Config()).Msg("[API] configuration file reloaded")
			}
			L.SetLevel(oldLevel)
			updatingGeo = false
		}()

		L.SetLevel(L.INFO)

		log.Info().Msg("[API] GEO databases updating...")

		if err = config.UpdateGeoDatabases(); err != nil {
			log.Error().Err(err).Msg("[API] update GEO databases failed")
			return
		}

		log.Info().Msg("[API] GEO databases updated")
		log.Info().Str("path", constant.Path.Config()).Msg("[API] configuration file reloading...")

		cfg, err = executor.ParseWithPath(constant.Path.Config())
		if err != nil {
			log.Error().
				Err(err).
				Str("path", constant.Path.Config()).
				Msg("[API] reload config failed")
			return
		}

		executor.ApplyConfig(cfg, false)
	}()

	render.NoContent(w, r)
}
