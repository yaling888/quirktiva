package h2

import (
	"context"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type Config struct {
	Hosts   []string
	Path    string
	Headers http.Header
}

var _ net.Conn = (*h2Conn)(nil)

type h2Conn struct {
	net.Conn
	*http2.ClientConn
	pWriter *io.PipeWriter
	resp    *http.Response
	cfg     *Config
	mux     sync.Mutex
	done    chan struct{}
	eErr    error
}

func (hc *h2Conn) establishConn() error {
	hc.mux.Lock()
	defer hc.mux.Unlock()

	select {
	case <-hc.done:
		return hc.eErr
	default:
	}

	defer func() {
		close(hc.done)
	}()

	pReader, pWriter := io.Pipe()

	host := hc.cfg.Hosts[rand.IntN(len(hc.cfg.Hosts))]
	path := hc.cfg.Path
	headers := hc.cfg.Headers
	headers.Del("Content-Type")
	headers.Del("Content-Length")
	headers.Set("Accept-Encoding", "identity")
	// TODO: connect use VMess Host instead of H2 Host
	req := &http.Request{
		Method: http.MethodPut,
		Host:   host,
		URL: &url.URL{
			Scheme: "https",
			Host:   host,
			Path:   path,
		},
		Proto:      "HTTP/2",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Body:       pReader,
		Header:     headers,
	}

	// it will be close at :  `func (hc *h2Conn) Close() error`
	resp, err := hc.ClientConn.RoundTrip(req)
	if err != nil {
		hc.eErr = err
		return err
	}

	hc.pWriter = pWriter
	hc.resp = resp

	return nil
}

func (hc *h2Conn) Read(b []byte) (n int, err error) {
	if hc.resp != nil {
		return hc.resp.Body.Read(b)
	}

	<-hc.done

	if hc.resp != nil {
		return hc.resp.Body.Read(b)
	}

	err = hc.eErr
	if err == nil {
		err = io.EOF
	}

	return
}

func (hc *h2Conn) Write(b []byte) (n int, err error) {
	if hc.pWriter != nil {
		return hc.pWriter.Write(b)
	}

	if err = hc.establishConn(); err != nil {
		return
	}

	if hc.pWriter != nil {
		return hc.pWriter.Write(b)
	}

	err = hc.eErr
	if err == nil {
		err = net.ErrClosed
	}

	return
}

func (hc *h2Conn) Close() error {
	if hc.pWriter != nil {
		if err := hc.pWriter.Close(); err != nil {
			return err
		}
	}
	var ctx context.Context
	if hc.resp != nil {
		ctx = hc.resp.Request.Context()
	} else {
		ctx1, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		ctx = ctx1
	}
	if err := hc.ClientConn.Shutdown(ctx); err != nil {
		return err
	}
	return hc.Conn.Close()
}

func StreamH2Conn(conn net.Conn, cfg *Config) (net.Conn, error) {
	transport := &http2.Transport{}

	cConn, err := transport.NewClientConn(conn)
	if err != nil {
		return nil, err
	}

	return &h2Conn{
		Conn:       conn,
		ClientConn: cConn,
		cfg:        cfg,
		done:       make(chan struct{}),
	}, nil
}
