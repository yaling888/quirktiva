package mitm

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/tunnel"
)

var _ C.RewriteHandler = (*RewriteHandler)(nil)

type RewriteHandler struct{}

func (*RewriteHandler) HandleRequest(session *C.MitmSession) (*http.Request, *http.Response) {
	var (
		request  = session.Request
		response *http.Response
	)

	rule, sub, found := matchRewriteRule(request.URL.String(), true)
	if !found {
		return nil, nil
	}

	switch rule.RuleType() {
	case C.MitmReject:
		response = session.NewResponse(http.StatusNotFound, nil)
		response.Header.Set("Content-Type", "text/html; charset=UTF-8")
	case C.MitmReject200:
		var payload string
		if len(rule.RulePayload()) > 0 {
			payload = rule.RulePayload()[0]
		}
		response = session.NewResponse(http.StatusOK, nil)
		if payload != "" {
			if strings.Contains(payload, "{") {
				response.Header.Set("Content-Type", "application/json; charset=UTF-8")
			} else {
				response.Header.Set("Content-Type", "text/plain; charset=UTF-8")
			}
			response.Body = io.NopCloser(strings.NewReader(payload))
			response.ContentLength = int64(len(payload))
		} else {
			response.Header.Set("Content-Type", "text/html; charset=UTF-8")
		}
	case C.MitmReject204:
		response = session.NewResponse(http.StatusNoContent, nil)
		response.Header.Set("Content-Type", "text/html; charset=UTF-8")
	case C.MitmRejectImg:
		response = session.NewResponse(http.StatusOK, OnePixelPNG.Body())
		response.Header.Set("Content-Type", "image/png")
		response.ContentLength = OnePixelPNG.ContentLength()
	case C.MitmRejectDict:
		response = session.NewResponse(http.StatusOK, EmptyDict.Body())
		response.Header.Set("Content-Type", "application/json; charset=UTF-8")
		response.ContentLength = EmptyDict.ContentLength()
	case C.MitmRejectArray:
		response = session.NewResponse(http.StatusOK, EmptyArray.Body())
		response.Header.Set("Content-Type", "application/json; charset=UTF-8")
		response.ContentLength = EmptyArray.ContentLength()
	case C.Mitm302:
		response = session.NewResponse(http.StatusFound, nil)
		response.Header.Set("Location", rule.ReplaceURLPayload(sub))
	case C.Mitm307:
		response = session.NewResponse(http.StatusTemporaryRedirect, nil)
		response.Header.Set("Location", rule.ReplaceURLPayload(sub))
	case C.MitmRequestHeader:
		if len(request.Header) == 0 {
			return nil, nil
		}

		rawHeader := &bytes.Buffer{}
		oldHeader := request.Header
		if err := oldHeader.Write(rawHeader); err != nil {
			return nil, nil
		}

		newRawHeader, ok := rule.ReplaceSubPayload(rawHeader.String())
		if !ok {
			return nil, nil
		}

		tb := textproto.NewReader(bufio.NewReader(strings.NewReader(newRawHeader)))
		newHeader, err := tb.ReadMIMEHeader()
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, nil
		}
		request.Header = http.Header(newHeader)
	case C.MitmRequestBody:
		if !CanRewriteBody(request.ContentLength, "", request.Header.Get("Content-Type")) {
			return nil, nil
		}

		buf := make([]byte, request.ContentLength)
		_, err := io.ReadFull(request.Body, buf)
		if err != nil {
			return nil, nil
		}

		newBody, _ := rule.ReplaceSubPayload(string(buf))
		request.Body = io.NopCloser(strings.NewReader(newBody))
		request.ContentLength = int64(len(newBody))
	default:
		found = false
	}

	if found {
		if response != nil {
			response.Close = true
		}
		return request, response
	}
	return nil, nil
}

func (*RewriteHandler) HandleResponse(session *C.MitmSession) *http.Response {
	var (
		request  = session.Request
		response = session.Response
	)

	rule, _, found := matchRewriteRule(request.URL.String(), false)
	found = found && rule.RuleRegx() != nil
	if !found {
		return nil
	}

	switch rule.RuleType() {
	case C.MitmResponseHeader:
		if len(response.Header) == 0 {
			return nil
		}

		rawHeader := &bytes.Buffer{}
		oldHeader := response.Header
		if err := oldHeader.Write(rawHeader); err != nil {
			return nil
		}

		newRawHeader, ok := rule.ReplaceSubPayload(rawHeader.String())
		if !ok {
			return nil
		}

		tb := textproto.NewReader(bufio.NewReader(strings.NewReader(newRawHeader)))
		newHeader, err := tb.ReadMIMEHeader()
		if err != nil && !errors.Is(err, io.EOF) {
			return nil
		}

		response.Header = http.Header(newHeader)
		response.Header.Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	case C.MitmResponseBody:
		contentType := response.Header.Get("Content-Type")
		if !CanRewriteBody(response.ContentLength, response.Header.Get("Content-Encoding"), contentType) {
			return nil
		}

		b, err := C.ReadDecompressedBody(response)
		_ = response.Body.Close()
		if err != nil {
			return nil
		}

		body := ""
		isUTF8 := strings.HasSuffix(strings.ToUpper(contentType), "UTF-8")
		if isUTF8 {
			body = string(b)
		} else {
			body, err = C.DecodeLatin1(bytes.NewReader(b))
			if err != nil {
				return nil
			}
		}

		newBody, _ := rule.ReplaceSubPayload(body)

		var modifiedBody []byte
		if isUTF8 {
			modifiedBody = []byte(newBody)
		} else {
			modifiedBody, err = C.EncodeLatin1(newBody)
			if err != nil {
				return nil
			}
		}

		response.Body = io.NopCloser(bytes.NewReader(modifiedBody))
		response.ContentLength = int64(len(modifiedBody))
		response.Header.Del("Content-Encoding")
		response.Header.Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	default:
		found = false
	}

	if found {
		return response
	}
	return nil
}

func (h *RewriteHandler) HandleApiRequest(*C.MitmSession) bool {
	return false
}

// HandleError session maybe nil
func (h *RewriteHandler) HandleError(*C.MitmSession, error) {}

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
