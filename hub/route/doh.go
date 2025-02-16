package route

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"unsafe"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/miekg/dns"
	"github.com/samber/lo"

	"github.com/yaling888/quirktiva/common/pool"
	"github.com/yaling888/quirktiva/component/resolver"
)

const (
	dotMimeType = "application/dns-message"
	paramKey    = "dns"
)

func dohRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", handleDoHDNS)
	r.Post("/", handleDoHDNS)
	return r
}

func handleDoHDNS(w http.ResponseWriter, r *http.Request) {
	if resolver.DefaultLocalServer == nil {
		render.Status(r, http.StatusInternalServerError)
		render.PlainText(w, r, "doh server is out of service")
		return
	}

	buf := pool.GetNetBuf()
	defer pool.PutNetBuf(buf)

	var (
		n   int
		err error
	)
	if r.Method == http.MethodPost {
		n, err = io.ReadFull(r.Body, *buf)
		if err != nil && err != io.ErrUnexpectedEOF {
			render.Status(r, http.StatusBadRequest)
			render.PlainText(w, r, err.Error())
			return
		}
	} else if b64 := r.URL.Query().Get(paramKey); b64 != "" {
		n, err = base64.RawURLEncoding.Decode(*buf, unsafe.Slice(unsafe.StringData(b64), len(b64)))
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.PlainText(w, r, err.Error())
			return
		}
	} else {
		render.Status(r, http.StatusBadRequest)
		render.PlainText(w, r, "no 'dns' query parameter found")
		return
	}

	msg := new(dns.Msg)
	if err = msg.Unpack((*buf)[:n]); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.PlainText(w, r, err.Error())
		return
	}

	var minTtl uint32
	msg.Id = 0
	m, err := resolver.ServeMsg(msg)
	if err == nil {
		m.Id = 0
		b, err := m.PackBuffer(*buf)
		if err == nil {
			if n = len(b); n <= pool.NetBufferSize {
				minObj := lo.MinBy(m.Answer, func(r1 dns.RR, r2 dns.RR) bool {
					return r1.Header().Ttl < r2.Header().Ttl
				})
				if minObj != nil {
					minTtl = minObj.Header().Ttl
				}
			} else {
				n, _ = handleMsgWithEmptyAnswer(msg, dns.RcodeServerFailure, *buf)
			}
		} else {
			n, _ = handleMsgWithEmptyAnswer(msg, dns.RcodeServerFailure, *buf)
		}
	} else {
		n, _ = handleMsgWithEmptyAnswer(msg, dns.RcodeServerFailure, *buf)
	}

	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", minTtl))
	w.Header().Set("Content-Type", dotMimeType)

	_, _ = w.Write((*buf)[:n])
}

func handleMsgWithEmptyAnswer(r *dns.Msg, code int, buf []byte) (int, error) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{}

	msg.SetRcode(r, code)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	b, err := msg.PackBuffer(buf)
	return len(b), err
}
