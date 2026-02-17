package mitm

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/phuslu/log"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"

	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/tunnel"
)

var _ C.RewriteHandler = (*RewriteHandler)(nil)

type RewriteHandler struct{}

func (*RewriteHandler) HandleRequest(rw http.ResponseWriter, req *http.Request) bool {
	url := req.URL.String()
	rule, sub, found := matchRewriteRule(url, true)
	if !found {
		return false
	}

	switch rule.RuleType() {
	case C.MitmReject:
		http.NotFoundHandler().ServeHTTP(rw, req)
		log.Debug().
			Any("type", C.MitmReject).
			Any("url", url).
			Msg("[MITM] rewrite request")
	case C.MitmReject200:
		var payload string
		if len(rule.RulePayload()) > 0 {
			payload = rule.RulePayload()[0]
		}
		if payload != "" {
			if s := payload[:1]; s == "{" || s == "[" {
				rw.Header().Set("Content-Type", "application/json; charset=UTF-8")
			} else {
				rw.Header().Set("Content-Type", "text/html; charset=UTF-8")
			}
			rw.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(rw, payload)
		} else {
			rw.WriteHeader(http.StatusOK)
		}
		log.Debug().
			Any("type", C.MitmReject200).
			Any("url", url).
			Msg("[MITM] rewrite request")
	case C.MitmReject204:
		rw.WriteHeader(http.StatusNoContent)
		log.Debug().
			Any("type", C.MitmReject204).
			Any("url", url).
			Msg("[MITM] rewrite request")
	case C.MitmRejectImg:
		rw.Header().Set("Content-Type", "image/png")
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(rw, OnePixelPNG)
		log.Debug().
			Any("type", C.MitmRejectImg).
			Any("url", url).
			Msg("[MITM] rewrite request")
	case C.MitmRejectDict:
		rw.Header().Set("Content-Type", "application/json; charset=UTF-8")
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(rw, EmptyDict)
		log.Debug().
			Any("type", C.MitmRejectDict).
			Any("url", url).
			Msg("[MITM] rewrite request")
	case C.MitmRejectArray:
		rw.Header().Set("Content-Type", "application/json; charset=UTF-8")
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(rw, EmptyArray)
		log.Debug().
			Any("type", C.MitmRejectArray).
			Any("url", url).
			Msg("[MITM] rewrite request")
	case C.Mitm302:
		to := rule.ReplaceURLPayload(sub)
		http.RedirectHandler(to, http.StatusFound).ServeHTTP(rw, req)
		log.Debug().
			Any("type", C.Mitm302).
			Any("from", url).
			Any("to", to).
			Msg("[MITM] rewrite request")
	case C.Mitm307:
		to := rule.ReplaceURLPayload(sub)
		http.RedirectHandler(to, http.StatusTemporaryRedirect).ServeHTTP(rw, req)
		log.Debug().
			Any("type", C.Mitm307).
			Any("from", url).
			Any("to", to).
			Msg("[MITM] rewrite request")
	case C.MitmRequestHeader:
		if len(req.Header) == 0 {
			return false
		}

		rawHeader := &bytes.Buffer{}
		oldHeader := req.Header
		if err := oldHeader.Write(rawHeader); err != nil {
			errorRequestHandler(rw, req, err)
			return true
		}

		newRawHeader, ok := rule.ReplaceSubPayload(rawHeader.String())
		if !ok {
			return false
		}

		tb := textproto.NewReader(bufio.NewReader(strings.NewReader(newRawHeader)))
		newHeader, err := tb.ReadMIMEHeader()
		if err != nil && !errors.Is(err, io.EOF) {
			errorRequestHandler(rw, req, err)
			return true
		}
		req.Header = http.Header(newHeader)
		log.Debug().
			Any("type", C.MitmRequestHeader).
			Any("url", url).
			Msg("[MITM] rewrite request")
		return false
	case C.MitmRequestBody:
		if req.Method == http.MethodHead || req.Method == http.MethodTrace ||
			req.Method == http.MethodOptions || req.Method == http.MethodConnect {
			return false
		}
		contentType := strings.ToLower(req.Header.Get("Content-Type"))
		contentEncoding := strings.ToLower(req.Header.Get("Content-Encoding"))
		isGzip := contentEncoding == "gzip"
		if (req.ContentLength <= 0 && !isGzip) || !canRewriteBody(contentType) {
			return false
		}

		body := req.Body
		if isGzip {
			if gr, err := gzip.NewReader(body); err == nil {
				defer gr.Close()
				body = gr
				req.Header.Del("Content-Encoding")
			} else {
				errorRequestHandler(rw, req, err)
				return true
			}
		}

		buf, err := io.ReadAll(body)
		if err != nil {
			errorRequestHandler(rw, req, err)
			return true
		}
		_ = req.Body.Close()

		newBody, _ := rule.ReplaceSubPayload(string(buf))
		req.Body = io.NopCloser(strings.NewReader(newBody))
		req.ContentLength = int64(len(newBody))
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
		log.Debug().
			Any("type", C.MitmRequestBody).
			Any("url", url).
			Msg("[MITM] rewrite request")
		return false
	default:
		return false
	}

	return true
}

func (*RewriteHandler) HandleResponse(res *http.Response) error {
	req := res.Request
	url := req.URL.String()
	rule, _, found := matchRewriteRule(url, false)
	found = found && rule.RuleRegx() != nil
	if !found {
		return nil
	}

	switch rule.RuleType() {
	case C.MitmResponseHeader:
		if len(res.Header) == 0 {
			return nil
		}

		rawHeader := &bytes.Buffer{}
		oldHeader := res.Header
		if err := oldHeader.Write(rawHeader); err != nil {
			return err
		}

		newRawHeader, ok := rule.ReplaceSubPayload(rawHeader.String())
		if !ok {
			return nil
		}

		tb := textproto.NewReader(bufio.NewReader(strings.NewReader(newRawHeader)))
		newHeader, err := tb.ReadMIMEHeader()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}

		newHeader.Set("Content-Length", strconv.FormatInt(res.ContentLength, 10))
		res.Header = http.Header(newHeader)
		log.Debug().
			Any("type", C.MitmResponseHeader).
			Any("url", url).
			Msg("[MITM] rewrite response")
	case C.MitmResponseBody:
		if req.Method == http.MethodHead || req.Method == http.MethodOptions || req.Method == http.MethodConnect {
			return nil
		}

		contentType := strings.ToLower(res.Header.Get("Content-Type"))
		contentEncoding := strings.ToLower(res.Header.Get("Content-Encoding"))
		isGzip := contentEncoding == "gzip"
		if (res.ContentLength <= 0 && !isGzip) || !canRewriteBody(contentType) {
			return nil
		}

		body := res.Body
		if isGzip {
			if gr, err := gzip.NewReader(body); err == nil {
				defer gr.Close()
				body = gr
			} else {
				return err
			}
		}

		_, a, ok := strings.Cut(contentType, "charset=")
		isUTF8 := !ok || a == "utf-8"
		if !isUTF8 {
			body = io.NopCloser(transform.NewReader(body, charmap.ISO8859_1.NewDecoder()))
		}

		b, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		_ = res.Body.Close()

		newBody, _ := rule.ReplaceSubPayload(string(b))

		var modifiedBody []byte
		if isUTF8 {
			modifiedBody = []byte(newBody)
		} else {
			modifiedBody, err = C.EncodeLatin1(newBody)
			if err != nil {
				return err
			}
		}

		if isGzip {
			w := &bytes.Buffer{}
			gw := gzip.NewWriter(w)
			_, err = gw.Write(modifiedBody)
			if err != nil {
				return err
			}
			_ = gw.Close()
			res.Body = io.NopCloser(w)
			if res.ContentLength > 0 {
				res.ContentLength = int64(w.Len())
				res.Header.Set("Content-Length", strconv.FormatInt(res.ContentLength, 10))
			}
		} else {
			res.Body = io.NopCloser(bytes.NewReader(modifiedBody))
			res.ContentLength = int64(len(modifiedBody))
			res.Header.Del("Content-Encoding")
			res.Header.Set("Content-Length", strconv.FormatInt(res.ContentLength, 10))
		}
		log.Debug().
			Any("type", C.MitmResponseBody).
			Any("url", url).
			Msg("[MITM] rewrite response")
	default:
	}
	return nil
}

func matchRewriteRule(url string, isRequest bool) (rr C.Rewrite, sub []string, found bool) {
	rewrites := tunnel.Rewrites()
	if isRequest {
		found = rewrites.SearchInRequest(func(r C.Rewrite) bool {
			// sub = r.URLRegx().FindStringSubmatch(url) // std
			sub = findStringSubmatch(r.URLRegx(), url)
			if len(sub) != 0 {
				rr = r
				return true
			}
			return false
		})
	} else {
		found = rewrites.SearchInResponse(func(r C.Rewrite) bool {
			// if r.URLRegx().FindString(url) != "" { // std
			if m, _ := r.URLRegx().MatchString(url); m {
				rr = r
				return true
			}
			return false
		})
	}

	return
}

func errorRequestHandler(rw http.ResponseWriter, req *http.Request, err error) {
	log.Error().Err(err).Str("url", req.URL.String()).Msg("[MITM] handle request")
	rw.WriteHeader(http.StatusBadGateway)
}
