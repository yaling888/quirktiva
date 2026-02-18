package mitm

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/klauspost/compress/zstd"
	"github.com/phuslu/log"
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
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
			Str("method", req.Method).
			Str("url", url).
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
				rw.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			}
			rw.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(rw, payload)
		} else {
			rw.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			rw.WriteHeader(http.StatusOK)
		}
		log.Debug().
			Any("type", C.MitmReject200).
			Str("method", req.Method).
			Str("url", url).
			Msg("[MITM] rewrite request")
	case C.MitmReject204:
		rw.WriteHeader(http.StatusNoContent)
		log.Debug().
			Any("type", C.MitmReject204).
			Str("method", req.Method).
			Str("url", url).
			Msg("[MITM] rewrite request")
	case C.MitmRejectImg:
		rw.Header().Set("Content-Type", "image/png")
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(rw, OnePixelPNG)
		log.Debug().
			Any("type", C.MitmRejectImg).
			Str("method", req.Method).
			Str("url", url).
			Msg("[MITM] rewrite request")
	case C.MitmRejectDict:
		rw.Header().Set("Content-Type", "application/json; charset=UTF-8")
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(rw, EmptyDict)
		log.Debug().
			Any("type", C.MitmRejectDict).
			Str("method", req.Method).
			Str("url", url).
			Msg("[MITM] rewrite request")
	case C.MitmRejectArray:
		rw.Header().Set("Content-Type", "application/json; charset=UTF-8")
		rw.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(rw, EmptyArray)
		log.Debug().
			Any("type", C.MitmRejectArray).
			Str("method", req.Method).
			Str("url", url).
			Msg("[MITM] rewrite request")
	case C.Mitm302:
		to := rule.ReplaceURLPayload(sub)
		http.RedirectHandler(to, http.StatusFound).ServeHTTP(rw, req)
		log.Debug().
			Any("type", C.Mitm302).
			Str("method", req.Method).
			Str("from", url).
			Str("to", to).
			Msg("[MITM] rewrite request")
	case C.Mitm307:
		to := rule.ReplaceURLPayload(sub)
		http.RedirectHandler(to, http.StatusTemporaryRedirect).ServeHTTP(rw, req)
		log.Debug().
			Any("type", C.Mitm307).
			Str("method", req.Method).
			Str("from", url).
			Str("to", to).
			Msg("[MITM] rewrite request")
	case C.MitmRequestHeader:
		if len(req.Header) == 0 || rule.RuleRegx() == nil {
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

		if req.ContentLength > 0 {
			newHeader.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
		} else {
			newHeader.Del("Content-Length")
		}
		req.Header = http.Header(newHeader)

		log.Debug().
			Any("type", C.MitmRequestHeader).
			Str("method", req.Method).
			Str("url", url).
			Msg("[MITM] rewrite request success")
		return false
	case C.MitmRequestHeaderJSON:
		if len(req.Header) == 0 || rule.RuleExpr() == nil {
			return false
		}

		originHeader := req.Header.Clone()

		rs, err := exprRun(rule.RuleExpr(), originHeader)
		if err != nil {
			log.Debug().
				Err(err).
				Any("type", C.MitmRequestHeaderJSON).
				Str("method", req.Method).
				Str("url", url).
				Msg("[MITM] rewrite request failed")
			return false
		}
		if !rs {
			log.Debug().
				Any("type", C.MitmRequestHeaderJSON).
				Str("method", req.Method).
				Str("url", url).
				Msg("[MITM] rewrite request failed, rewrite nothing")
			return false
		}

		if req.ContentLength > 0 {
			originHeader.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
		} else {
			originHeader.Del("Content-Length")
		}
		req.Header = originHeader

		log.Debug().
			Any("type", C.MitmRequestHeaderJSON).
			Str("method", req.Method).
			Str("url", url).
			Msg("[MITM] rewrite request success")
		return false
	case C.MitmRequestBody:
		if req.Method == http.MethodHead || req.Method == http.MethodOptions ||
			req.Method == http.MethodConnect || rule.RuleRegx() == nil {
			return false
		}

		mediaType, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil || !canRewriteBody(mediaType) {
			return false
		}

		contentEncoding := strings.ToLower(req.Header.Get("Content-Encoding"))
		charsetEncoding := pickCharsetEncoding(params["charset"])

		originBody := &bytes.Buffer{}
		data, err := readBody(io.TeeReader(req.Body, originBody), charsetEncoding, contentEncoding)
		if err != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			req.Body = io.NopCloser(originBody)

			log.Debug().
				Err(err).
				Any("type", C.MitmRequestBody).
				Str("method", req.Method).
				Str("host", req.Host).
				Msg("[MITM] rewrite request failed")
			return false
		}

		modifiedBody, ok := rule.ReplaceSubPayload(data.String())
		if !ok || modifiedBody == "" {
			req.Body = io.NopCloser(originBody)

			log.Debug().
				Any("type", C.MitmRequestBody).
				Str("method", req.Method).
				Str("host", req.Host).
				Msg("[MITM] rewrite request failed, rewrite nothing")
			return false
		}

		newBody := &bytes.Buffer{}
		if err = writeBody(newBody, []byte(modifiedBody), charsetEncoding); err != nil {
			clear(newBody.Bytes())
			newBody.Reset()
			req.Body = io.NopCloser(originBody)

			log.Debug().
				Err(err).
				Any("type", C.MitmRequestBody).
				Str("method", req.Method).
				Str("host", req.Host).
				Msg("[MITM] rewrite request failed")
			return false
		}

		clear(originBody.Bytes())
		originBody.Reset()

		req.Body = io.NopCloser(newBody)
		req.ContentLength = int64(newBody.Len())
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
		req.Header.Del("Content-Encoding")

		log.Debug().
			Any("type", C.MitmRequestBody).
			Str("method", req.Method).
			Str("url", url).
			Msg("[MITM] rewrite request success")
		return false
	case C.MitmRequestBodyJSON:
		if req.Method == http.MethodHead || req.Method == http.MethodOptions ||
			req.Method == http.MethodConnect || rule.RuleExpr() == nil {
			return false
		}

		mediaType, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return false
		}

		contentEncoding := strings.ToLower(req.Header.Get("Content-Encoding"))
		charsetEncoding := pickCharsetEncoding(params["charset"])

		originBody := &bytes.Buffer{}
		data, err := readJSONBody(io.TeeReader(req.Body, originBody), charsetEncoding, contentEncoding, false)
		if err != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			clear(originBody.Bytes())
			originBody.Reset()
			errorRequestHandler(rw, req, err)
			return true
		}

		rs, err := exprRun(rule.RuleExpr(), data)
		if err != nil {
			req.Body = io.NopCloser(originBody)

			log.Debug().
				Err(err).
				Any("type", C.MitmRequestBodyJSON).
				Str("method", req.Method).
				Str("host", req.Host).
				Msg("[MITM] rewrite request failed")
			return false
		}
		if !rs {
			req.Body = io.NopCloser(originBody)

			log.Debug().
				Any("type", C.MitmRequestBodyJSON).
				Str("method", req.Method).
				Str("host", req.Host).
				Msg("[MITM] rewrite request failed, rewrite nothing")
			return false
		}

		newBody := &bytes.Buffer{}
		if err = writeJSONBody(newBody, data, charsetEncoding, false); err != nil {
			clear(newBody.Bytes())
			newBody.Reset()
			req.Body = io.NopCloser(originBody)

			log.Debug().
				Err(err).
				Any("type", C.MitmRequestBodyJSON).
				Str("method", req.Method).
				Str("host", req.Host).
				Msg("[MITM] rewrite request failed")
			return false
		}

		clear(originBody.Bytes())
		originBody.Reset()

		req.Body = io.NopCloser(newBody)
		req.ContentLength = int64(newBody.Len())
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
		req.Header.Del("Content-Encoding")

		log.Debug().
			Any("type", C.MitmRequestBodyJSON).
			Str("method", req.Method).
			Str("url", url).
			Msg("[MITM] rewrite request success")
		return false
	default:
		return false
	}

	return true
}

func (*RewriteHandler) HandleResponse(resp *http.Response) error {
	req := resp.Request
	url := req.URL.String()
	rule, _, found := matchRewriteRule(url, false)
	if !found {
		return nil
	}

	switch rule.RuleType() {
	case C.MitmResponseHeader:
		if len(resp.Header) == 0 || rule.RuleRegx() == nil {
			return nil
		}

		rawHeader := &bytes.Buffer{}
		oldHeader := resp.Header
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

		if resp.ContentLength > 0 {
			newHeader.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		} else {
			newHeader.Del("Content-Length")
		}
		resp.Header = http.Header(newHeader)

		log.Debug().
			Any("type", C.MitmResponseHeader).
			Str("method", req.Method).
			Str("url", url).
			Msg("[MITM] rewrite response success")
	case C.MitmResponseHeaderJSON:
		if len(resp.Header) == 0 || rule.RuleExpr() == nil {
			return nil
		}

		originHeader := resp.Header.Clone()

		rs, err := exprRun(rule.RuleExpr(), originHeader)
		if err != nil {
			return err
		}
		if !rs {
			log.Debug().
				Any("type", C.MitmResponseHeaderJSON).
				Str("method", req.Method).
				Str("url", url).
				Msg("[MITM] rewrite response failed, rewrite nothing")
			return nil
		}

		if resp.ContentLength > 0 {
			originHeader.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		} else {
			originHeader.Del("Content-Length")
		}
		resp.Header = originHeader

		log.Debug().
			Any("type", C.MitmResponseHeaderJSON).
			Str("method", req.Method).
			Str("url", url).
			Msg("[MITM] rewrite response success")
	case C.MitmResponseBody:
		if req.Method == http.MethodHead || req.Method == http.MethodOptions ||
			req.Method == http.MethodConnect || rule.RuleRegx() == nil {
			return nil
		}

		contentType := resp.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err != nil || !canRewriteBody(mediaType) {
			return nil
		}

		contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
		charset := params["charset"]
		charsetEncoding := pickCharsetEncoding(charset)

		originBody := &bytes.Buffer{}
		data, err := readBody(io.TeeReader(resp.Body, originBody), charsetEncoding, contentEncoding)
		if err != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			resp.Body = io.NopCloser(originBody)

			log.Debug().
				Err(err).
				Any("type", C.MitmResponseBody).
				Str("method", req.Method).
				Str("charset", charset).
				Str("encoding", contentEncoding).
				Str("contentType", contentType).
				Str("url", url).
				Msg("[MITM] rewrite response failed")
			return nil
		}
		_ = resp.Body.Close()

		modifiedBody, ok := rule.ReplaceSubPayload(data.String())
		if !ok || modifiedBody == "" {
			resp.Body = io.NopCloser(originBody)

			log.Debug().
				Any("type", C.MitmResponseBody).
				Str("method", req.Method).
				Str("charset", charset).
				Str("encoding", contentEncoding).
				Str("contentType", contentType).
				Str("url", url).
				Msg("[MITM] rewrite response failed, rewrite nothing")
			return nil
		}

		newBody := &bytes.Buffer{}
		if err = writeBody(newBody, []byte(modifiedBody), charsetEncoding); err != nil {
			clear(newBody.Bytes())
			newBody.Reset()
			resp.Body = io.NopCloser(originBody)

			log.Debug().
				Err(err).
				Any("type", C.MitmResponseBody).
				Str("method", req.Method).
				Str("charset", charset).
				Str("encoding", contentEncoding).
				Str("contentType", contentType).
				Str("url", url).
				Msg("[MITM] rewrite response failed")
			return nil
		}

		clear(originBody.Bytes())
		originBody.Reset()

		resp.Body = io.NopCloser(newBody)
		resp.ContentLength = int64(newBody.Len())
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		resp.Header.Del("Content-Encoding")

		log.Debug().
			Any("type", C.MitmResponseBody).
			Str("method", req.Method).
			Str("charset", charset).
			Str("encoding", contentEncoding).
			Str("contentType", contentType).
			Str("url", url).
			Msg("[MITM] rewrite response success")
	case C.MitmResponseBodyJSON:
		if req.Method == http.MethodHead || req.Method == http.MethodOptions ||
			req.Method == http.MethodConnect || rule.RuleExpr() == nil {
			return nil
		}

		contentType := resp.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err != nil {
			log.Debug().
				Err(err).
				Any("type", C.MitmResponseBodyJSON).
				Str("method", req.Method).
				Str("contentType", contentType).
				Str("url", url).
				Msg("[MITM] rewrite response failed")
			return nil
		}
		if mediaType != "application/json" {
			log.Debug().
				Any("type", C.MitmResponseBodyJSON).
				Str("method", req.Method).
				Str("contentType", contentType).
				Str("url", url).
				Msg("[MITM] rewrite response failed, invalid content type")
			return nil
		}

		contentEncoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
		_, isBase64 := params["base64"]
		charset := params["charset"]
		charsetEncoding := pickCharsetEncoding(charset)

		originBody := &bytes.Buffer{}
		data, err := readJSONBody(io.TeeReader(resp.Body, originBody), charsetEncoding, contentEncoding, isBase64)
		if err != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			clear(originBody.Bytes())
			originBody.Reset()
			return fmt.Errorf("rewrite response failed, error: %w", err)
		}
		_ = resp.Body.Close()

		rs, err := exprRun(rule.RuleExpr(), data)
		if err != nil {
			resp.Body = io.NopCloser(originBody)

			log.Debug().
				Err(err).
				Any("type", C.MitmResponseBodyJSON).
				Str("method", req.Method).
				Str("charset", charset).
				Str("encoding", contentEncoding).
				Bool("base64", isBase64).
				Str("url", url).
				Msg("[MITM] rewrite response failed")
			return nil
		}
		if !rs {
			resp.Body = io.NopCloser(originBody)

			log.Debug().
				Any("type", C.MitmResponseBodyJSON).
				Str("method", req.Method).
				Str("charset", charset).
				Str("encoding", contentEncoding).
				Bool("base64", isBase64).
				Str("url", url).
				Msg("[MITM] rewrite response failed, rewrite nothing")
			return nil
		}

		newBody := &bytes.Buffer{}
		if err = writeJSONBody(newBody, data, charsetEncoding, isBase64); err != nil {
			clear(newBody.Bytes())
			newBody.Reset()
			resp.Body = io.NopCloser(originBody)

			log.Debug().
				Err(err).
				Any("type", C.MitmResponseBodyJSON).
				Str("method", req.Method).
				Str("charset", charset).
				Str("encoding", contentEncoding).
				Bool("base64", isBase64).
				Str("url", url).
				Msg("[MITM] rewrite response failed")
			return nil
		}

		clear(originBody.Bytes())
		originBody.Reset()

		resp.Body = io.NopCloser(newBody)
		resp.ContentLength = int64(newBody.Len())
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
		resp.Header.Del("Content-Encoding")

		log.Debug().
			Any("type", C.MitmResponseBodyJSON).
			Str("method", req.Method).
			Str("charset", charset).
			Str("encoding", contentEncoding).
			Bool("base64", isBase64).
			Str("url", url).
			Msg("[MITM] rewrite response success")
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

func readBody(r io.Reader, charsetEnc encoding.Encoding, contentEncoding string) (body *bytes.Buffer, err error) {
	if contentEncoding != "" {
		cr, err := pickContentEncoding(contentEncoding, r)
		if err != nil {
			return body, err
		}
		defer cr.Close()
		r = cr
	}

	if charsetEnc != nil {
		r = transform.NewReader(r, charsetEnc.NewDecoder())
	}

	body = &bytes.Buffer{}
	_, err = body.ReadFrom(r)
	return body, err
}

func writeBody(w io.Writer, body []byte, charsetEnc encoding.Encoding) error {
	if charsetEnc != nil {
		cw := transform.NewWriter(w, charsetEnc.NewEncoder())
		defer cw.Close()
		w = cw
	}

	_, err := w.Write(body)
	return err
}

func readJSONBody(r io.Reader, charsetEnc encoding.Encoding, contentEncoding string, isBase64 bool) (body any, err error) {
	if contentEncoding != "" {
		cr, err := pickContentEncoding(contentEncoding, r)
		if err != nil {
			return nil, err
		}
		defer cr.Close()
		r = cr
	}

	if isBase64 {
		r = base64.NewDecoder(base64.StdEncoding, r)
	}

	if charsetEnc != nil {
		r = transform.NewReader(r, charsetEnc.NewDecoder())
	}

	br := bufio.NewReader(r)
	buf, err := br.Peek(2)
	if err != nil {
		return nil, err
	}
	if br.Buffered() > 2 {
		buf, err = br.Peek(br.Buffered())
		if err != nil {
			return nil, err
		}
	}
	buf = bytes.TrimLeft(buf, " \n")
	if bytes.HasPrefix(buf, []byte("{")) {
		body = map[string]any{}
	} else if bytes.HasPrefix(buf, []byte("[")) {
		body = []any{}
	} else {
		return nil, errors.New("body is not a json data")
	}

	r = br

	err = json.NewDecoder(r).Decode(&body)
	return body, err
}

func writeJSONBody(w io.Writer, body any, charsetEnc encoding.Encoding, isBase64 bool) error {
	if isBase64 {
		bw := base64.NewEncoder(base64.StdEncoding, w)
		defer bw.Close()
		w = bw
	}

	if charsetEnc != nil {
		cw := transform.NewWriter(w, charsetEnc.NewEncoder())
		defer cw.Close()
		w = cw
	}

	return json.NewEncoder(w).Encode(body)
}

type zstdWrapper struct {
	*zstd.Decoder
}

func (z *zstdWrapper) Close() error {
	z.Decoder.Close()
	return nil
}

// must be call Reader.Close when done.
func pickContentEncoding(contentEncoding string, r io.Reader) (io.ReadCloser, error) {
	switch contentEncoding {
	case "gzip":
		return gzip.NewReader(r)
	case "zstd":
		z, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return &zstdWrapper{z}, nil
	case "br":
		return io.NopCloser(brotli.NewReader(r)), nil
	case "deflate":
		return flate.NewReader(r), nil
	}
	return nil, fmt.Errorf("content encoding not supported: %s", contentEncoding)
}

func pickCharsetEncoding(charset string) encoding.Encoding {
	if charset == "" || charset == "utf-8" {
		return nil
	}
	if enc, err := htmlindex.Get(charset); err == nil { // maybe should use charset.DetermineEncoding()? but ...
		return enc
	}
	return nil
}

func exprRun(program *vm.Program, data any) (bool, error) {
	switch v := data.(type) {
	case map[string]any:
		output, err := expr.Run(program, Env{Data: v})
		if err != nil {
			return false, err
		}
		return output.(bool), nil
	case []any:
		var rs bool
		for i := 0; i < len(v); i++ {
			if m, ok := v[i].(map[string]any); ok {
				output, err := expr.Run(program, Env{Data: m})
				if err != nil {
					return false, err
				}
				rs1 := output.(bool)
				rs = rs || rs1
			}
		}
		return rs, nil
	default:
		return false, nil
	}
}

func errorRequestHandler(rw http.ResponseWriter, req *http.Request, err error) {
	log.Error().Err(err).Str("url", req.URL.String()).Msg("[MITM] handle request")
	rw.WriteHeader(http.StatusBadGateway)
}
