package provider

import (
	"bytes"
	"crypto/md5"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/phuslu/log"
	"github.com/samber/lo"

	types "github.com/Dreamacro/clash/constant/provider"
)

var (
	fileMode os.FileMode = 0o666
	dirMode  os.FileMode = 0o755

	commentRegx = regexp.MustCompile(`(.*#.*\n)`)
)

type parser[V any] func([]byte) (V, error)

type fetcher[V any] struct {
	name      string
	vehicle   types.Vehicle
	interval  time.Duration
	updatedAt *time.Time
	ticker    *time.Ticker
	done      chan struct{}
	hash      [16]byte
	parser    parser[V]
	onUpdate  func(V)
}

func (f *fetcher[V]) Name() string {
	return f.name
}

func (f *fetcher[V]) VehicleType() types.VehicleType {
	return f.vehicle.Type()
}

func (f *fetcher[V]) Initial() (V, error) {
	var (
		buf               []byte
		err               error
		isLocal           bool
		immediatelyUpdate bool
	)
	if stat, fErr := os.Stat(f.vehicle.Path()); fErr == nil {
		buf, err = os.ReadFile(f.vehicle.Path())
		modTime := stat.ModTime()
		f.updatedAt = &modTime
		isLocal = true
		immediatelyUpdate = f.interval != 0 && time.Since(modTime) > f.interval
	} else {
		buf, err = f.vehicle.Read()
	}

	if err != nil {
		return lo.Empty[V](), err
	}

	proxies, err := f.parser(buf)
	if err != nil {
		if !isLocal {
			return lo.Empty[V](), err
		}

		// parse local file error, fallback to remote
		buf, err = f.vehicle.Read()
		if err != nil {
			return lo.Empty[V](), err
		}

		proxies, err = f.parser(buf)
		if err != nil {
			return lo.Empty[V](), err
		}

		isLocal = false
	}

	if f.vehicle.Type() != types.File && !isLocal {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return lo.Empty[V](), err
		}
	}

	f.hash = md5.Sum(buf)

	// pull proxies automatically
	if f.ticker != nil {
		go f.pullLoop(immediatelyUpdate)
	}

	return proxies, nil
}

func (f *fetcher[V]) Update() (V, bool, error) {
	buf, err := f.vehicle.Read()
	if err != nil {
		return lo.Empty[V](), false, err
	}

	now := time.Now()
	hash := md5.Sum(buf)
	if bytes.Equal(f.hash[:], hash[:]) {
		f.updatedAt = &now
		_ = os.Chtimes(f.vehicle.Path(), now, now)
		return lo.Empty[V](), true, nil
	}

	proxies, err := f.parser(buf)
	if err != nil {
		return lo.Empty[V](), false, err
	}

	if f.vehicle.Type() != types.File {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return lo.Empty[V](), false, err
		}
	}

	f.updatedAt = &now
	f.hash = hash

	return proxies, false, nil
}

func (f *fetcher[V]) Destroy() error {
	if f.ticker != nil {
		select {
		case f.done <- struct{}{}:
		default:
		}
	}
	return nil
}

func (f *fetcher[V]) pullLoop(immediately bool) {
	update := func() {
		log.Debug().Str("name", f.Name()).Msg("[Provider] proxies updating...")
		elm, same, err := f.Update()
		if err != nil {
			log.Warn().Err(err).Str("name", f.Name()).Msg("[Provider] pull failed")
			return
		}

		if same {
			log.Debug().Str("name", f.Name()).Msg("[Provider] proxies doesn't change")
			return
		}

		log.Info().Str("name", f.Name()).Msg("[Provider] proxies updated")
		if f.onUpdate != nil {
			f.onUpdate(elm)
		}
	}

	if immediately {
		update()
	}

	for {
		select {
		case <-f.ticker.C:
			update()
		case <-f.done:
			f.ticker.Stop()
			return
		}
	}
}

func safeWrite(path string, buf []byte) error {
	dir := filepath.Dir(path)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}

	return os.WriteFile(path, buf, fileMode)
}

func removeComment(buf []byte) []byte {
	arr := commentRegx.FindAllSubmatch(buf, -1)
	for _, subs := range arr {
		sub := subs[0]
		if !bytes.HasPrefix(bytes.TrimLeft(sub, " 	"), []byte("#")) {
			continue
		}
		buf = bytes.Replace(buf, sub, []byte(""), 1)
	}
	return buf
}

func newFetcher[V any](name string, interval time.Duration, vehicle types.Vehicle, parser parser[V], onUpdate func(V)) *fetcher[V] {
	var ticker *time.Ticker
	if interval != 0 {
		ticker = time.NewTicker(interval)
	}

	return &fetcher[V]{
		name:     name,
		ticker:   ticker,
		vehicle:  vehicle,
		interval: interval,
		parser:   parser,
		done:     make(chan struct{}, 1),
		onUpdate: onUpdate,
	}
}
