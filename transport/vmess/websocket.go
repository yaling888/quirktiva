package vmess

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yaling888/quirktiva/transport/h1"
	tls2 "github.com/yaling888/quirktiva/transport/tls"
)

type websocketConn struct {
	conn       *websocket.Conn
	reader     io.Reader
	remoteAddr net.Addr

	// https://godoc.org/github.com/gorilla/websocket#hdr-Concurrency
	rMux sync.Mutex
	wMux sync.Mutex
}

type websocketWithEarlyDataConn struct {
	net.Conn
	underlay net.Conn
	closed   bool
	dialed   chan bool
	cancel   context.CancelFunc
	ctx      context.Context
	config   *WebsocketConfig
}

type WebsocketConfig struct {
	Host                string
	Port                string
	Path                string
	Headers             http.Header
	TLS                 bool
	TLSConfig           *tls.Config
	MaxEarlyData        int
	EarlyDataHeaderName string
	V2rayHTTPUpgrade    bool
}

// Read implements net.Conn.Read()
func (wsc *websocketConn) Read(b []byte) (int, error) {
	wsc.rMux.Lock()
	defer wsc.rMux.Unlock()
	for {
		reader, err := wsc.getReader()
		if err != nil {
			return 0, err
		}

		nBytes, err := reader.Read(b)
		if err == io.EOF {
			wsc.reader = nil
			continue
		}
		return nBytes, err
	}
}

// Write implements io.Writer.
func (wsc *websocketConn) Write(b []byte) (int, error) {
	wsc.wMux.Lock()
	defer wsc.wMux.Unlock()
	if err := wsc.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (wsc *websocketConn) Close() error {
	var errs error
	if err := wsc.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5)); err != nil {
		errs = err
	}
	if err := wsc.conn.Close(); err != nil {
		if errs == nil {
			errs = err
		} else {
			errs = fmt.Errorf("%w, %w", errs, err)
		}
	}
	if errs != nil {
		return fmt.Errorf("failed to close connection: %w", errs)
	}
	return nil
}

func (wsc *websocketConn) getReader() (io.Reader, error) {
	if wsc.reader != nil {
		return wsc.reader, nil
	}

	_, reader, err := wsc.conn.NextReader()
	if err != nil {
		return nil, err
	}
	wsc.reader = reader
	return reader, nil
}

func (wsc *websocketConn) LocalAddr() net.Addr {
	return wsc.conn.LocalAddr()
}

func (wsc *websocketConn) RemoteAddr() net.Addr {
	return wsc.remoteAddr
}

func (wsc *websocketConn) SetDeadline(t time.Time) error {
	if err := wsc.SetReadDeadline(t); err != nil {
		return err
	}
	return wsc.SetWriteDeadline(t)
}

func (wsc *websocketConn) SetReadDeadline(t time.Time) error {
	return wsc.conn.SetReadDeadline(t)
}

func (wsc *websocketConn) SetWriteDeadline(t time.Time) error {
	return wsc.conn.SetWriteDeadline(t)
}

func (wsedc *websocketWithEarlyDataConn) Dial(earlyData []byte) error {
	base64DataBuf := &bytes.Buffer{}
	base64EarlyDataEncoder := base64.NewEncoder(base64.RawURLEncoding, base64DataBuf)

	earlyDataBuf := bytes.NewBuffer(earlyData)
	if _, err := base64EarlyDataEncoder.Write(earlyDataBuf.Next(wsedc.config.MaxEarlyData)); err != nil {
		return fmt.Errorf("failed to encode early data: %w", err)
	}

	if errc := base64EarlyDataEncoder.Close(); errc != nil {
		return fmt.Errorf("failed to encode early data tail: %w", errc)
	}

	var err error
	if wsedc.Conn, err = streamWebsocketConn(wsedc.underlay, wsedc.config, base64DataBuf); err != nil {
		_ = wsedc.Close()
		return fmt.Errorf("failed to dial WebSocket: %w", err)
	}

	wsedc.dialed <- true
	if earlyDataBuf.Len() != 0 {
		_, err = wsedc.Conn.Write(earlyDataBuf.Bytes())
	}

	return err
}

func (wsedc *websocketWithEarlyDataConn) Write(b []byte) (int, error) {
	if wsedc.closed {
		return 0, io.ErrClosedPipe
	}
	if wsedc.Conn == nil {
		if err := wsedc.Dial(b); err != nil {
			return 0, err
		}
		return len(b), nil
	}

	return wsedc.Conn.Write(b)
}

func (wsedc *websocketWithEarlyDataConn) Read(b []byte) (int, error) {
	if wsedc.closed {
		return 0, io.ErrClosedPipe
	}
	if wsedc.Conn == nil {
		select {
		case <-wsedc.ctx.Done():
			return 0, io.ErrUnexpectedEOF
		case <-wsedc.dialed:
		}
	}
	return wsedc.Conn.Read(b)
}

func (wsedc *websocketWithEarlyDataConn) Close() error {
	wsedc.closed = true
	wsedc.cancel()
	if wsedc.Conn == nil {
		return nil
	}
	return wsedc.Conn.Close()
}

func (wsedc *websocketWithEarlyDataConn) LocalAddr() net.Addr {
	if wsedc.Conn == nil {
		return wsedc.underlay.LocalAddr()
	}
	return wsedc.Conn.LocalAddr()
}

func (wsedc *websocketWithEarlyDataConn) RemoteAddr() net.Addr {
	if wsedc.Conn == nil {
		return wsedc.underlay.RemoteAddr()
	}
	return wsedc.Conn.RemoteAddr()
}

func (wsedc *websocketWithEarlyDataConn) SetDeadline(t time.Time) error {
	if err := wsedc.SetReadDeadline(t); err != nil {
		return err
	}
	return wsedc.SetWriteDeadline(t)
}

func (wsedc *websocketWithEarlyDataConn) SetReadDeadline(t time.Time) error {
	if wsedc.Conn == nil {
		return nil
	}
	return wsedc.Conn.SetReadDeadline(t)
}

func (wsedc *websocketWithEarlyDataConn) SetWriteDeadline(t time.Time) error {
	if wsedc.Conn == nil {
		return nil
	}
	return wsedc.Conn.SetWriteDeadline(t)
}

func streamWebsocketWithEarlyDataConn(conn net.Conn, c *WebsocketConfig) (net.Conn, error) {
	ctx, cancel := context.WithCancel(context.Background())
	conn = &websocketWithEarlyDataConn{
		dialed:   make(chan bool, 1),
		cancel:   cancel,
		ctx:      ctx,
		underlay: conn,
		config:   c,
	}
	return conn, nil
}

func streamWebsocketConn(conn net.Conn, c *WebsocketConfig, earlyData *bytes.Buffer) (net.Conn, error) {
	u, err := url.Parse(c.Path)
	if err != nil {
		return nil, fmt.Errorf("parse url %s error: %w", c.Path, err)
	}

	uri := url.URL{
		Scheme:   "http",
		Host:     net.JoinHostPort(c.Host, c.Port),
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}

	if c.TLSConfig != nil {
		conn, err = tls2.StreamTLSConn(conn, c.TLSConfig)
		if err != nil {
			return nil, err
		}
		uri.Scheme = "https"
	}

	headers := http.Header{}
	if c.Headers != nil {
		headers = c.Headers.Clone()
	}

	if c.V2rayHTTPUpgrade {
		return h1.StreamHTTPUpgrade(conn, uri.String(), headers)
	}

	if earlyData != nil {
		if c.EarlyDataHeaderName == "" {
			uri.Path += earlyData.String()
		} else {
			headers.Set(c.EarlyDataHeaderName, earlyData.String())
		}
	}

	dialer := &websocket.Dialer{
		ReadBufferSize:  4 * 1024,
		WriteBufferSize: 4 * 1024,
	}

	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return conn, nil
	}
	if c.TLSConfig != nil {
		uri.Scheme = "wss"
		dialer.NetDialTLSContext = dialFn
	} else {
		uri.Scheme = "ws"
		dialer.NetDialContext = dialFn
	}

	wsConn, resp, err := dialer.Dial(uri.String(), headers)
	if err != nil {
		if resp != nil {
			err = fmt.Errorf("%w: status: %s", err, resp.Status)
		}
		return nil, fmt.Errorf("dial %s error: %w", uri.Host, err)
	}

	return &websocketConn{
		conn:       wsConn,
		remoteAddr: conn.RemoteAddr(),
	}, nil
}

func StreamWebsocketConn(conn net.Conn, c *WebsocketConfig) (net.Conn, error) {
	if u, err := url.Parse(c.Path); err == nil {
		if q := u.Query(); q.Get("ed") != "" {
			if ed, err := strconv.Atoi(q.Get("ed")); err == nil {
				c.MaxEarlyData = ed
				c.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
				q.Del("ed")
				u.RawQuery = q.Encode()
				c.Path = u.String()
			}
		}
	}

	if c.MaxEarlyData > 0 && !c.V2rayHTTPUpgrade {
		return streamWebsocketWithEarlyDataConn(conn, c)
	}

	return streamWebsocketConn(conn, c, nil)
}
