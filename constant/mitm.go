package constant

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"

	"github.com/yaling888/quirktiva/common/cert"
)

var (
	ErrInvalidResponse = errors.New("invalid response")
	ErrInvalidURL      = errors.New("invalid URL")
)

type RewriteHandler interface {
	HandleRequest(*MitmSession) (*http.Request, *http.Response) // session.Response maybe nil
	HandleResponse(*MitmSession) *http.Response
	HandleApiRequest(*MitmSession) bool
	HandleError(*MitmSession, error) // session maybe nil
}

type MitmOption struct {
	ApiHost string

	TLSConfig  *tls.Config
	CertConfig *cert.Config

	Handler RewriteHandler
}

type MitmSession struct {
	Conn     net.Conn
	Request  *http.Request
	Response *http.Response

	props map[string]any
}

func (s *MitmSession) GetProperties(key string) (any, bool) {
	v, ok := s.props[key]
	return v, ok
}

func (s *MitmSession) SetProperties(key string, val any) {
	s.props[key] = val
}

func (s *MitmSession) NewResponse(code int, body io.Reader) *http.Response {
	return NewResponse(code, body, s.Request)
}

func (s *MitmSession) NewErrorResponse(err error) *http.Response {
	return NewErrorResponse(s.Request, err)
}

func (s *MitmSession) WriteResponse() (err error) {
	if s.Response == nil {
		return ErrInvalidResponse
	}
	err = s.Response.Write(s.Conn)
	if s.Response.Body != nil {
		_ = s.Response.Body.Close()
	}
	return
}

func NewMitmSession(conn net.Conn, request *http.Request, response *http.Response) *MitmSession {
	return &MitmSession{
		Conn:     conn,
		Request:  request,
		Response: response,
		props:    map[string]any{},
	}
}

func NewResponse(code int, body io.Reader, req *http.Request) *http.Response {
	if body == nil {
		body = &bytes.Buffer{}
	}

	rc, ok := body.(io.ReadCloser)
	if !ok {
		rc = io.NopCloser(body)
	}

	res := &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       rc,
		Request:    req,
	}

	if req != nil {
		res.Close = req.Close
		res.Proto = req.Proto
		res.ProtoMajor = req.ProtoMajor
		res.ProtoMinor = req.ProtoMinor
	}

	return res
}

func NewErrorResponse(req *http.Request, err error) *http.Response {
	res := NewResponse(http.StatusBadGateway, nil, req)
	res.Close = true

	date := res.Header.Get("Date")
	if date == "" {
		date = time.Now().Format(http.TimeFormat)
	}

	w := fmt.Sprintf(`199 "quirktiva" %s %s`, err.Error(), date)
	res.Header.Add("Warning", w)
	return res
}

func ReadDecompressedBody(res *http.Response) ([]byte, error) {
	rBody := res.Body
	if res.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(rBody)
		if err != nil {
			return nil, err
		}
		rBody = gzReader

		defer func(gzReader *gzip.Reader) {
			_ = gzReader.Close()
		}(gzReader)
	}
	return io.ReadAll(rBody)
}

func DecodeLatin1(reader io.Reader) (string, error) {
	r := transform.NewReader(reader, charmap.ISO8859_1.NewDecoder())
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func EncodeLatin1(str string) ([]byte, error) {
	return charmap.ISO8859_1.NewEncoder().Bytes([]byte(str))
}
