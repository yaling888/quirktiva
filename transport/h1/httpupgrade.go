package h1

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

// HTTPUpgrade is v2ray httpupgrade implementation
type HTTPUpgrade struct {
	net.Conn
	reader *bufio.Reader
}

func (hu *HTTPUpgrade) Read(b []byte) (int, error) {
	return hu.reader.Read(b)
}

func (hu *HTTPUpgrade) handshake(ctx context.Context, url string, requestHeader http.Header) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "upgrade")

	for k, vs := range requestHeader {
		switch k {
		case "Upgrade", "Connection", "Sec-Websocket-Key", "Sec-Websocket-Version",
			"Sec-Websocket-Extensions", "Sec-Websocket-Protocol":
			continue
		case "Host":
			if len(vs) > 0 {
				req.Host = vs[0]
			}
		default:
			req.Header[k] = vs
		}
	}

	switch req.URL.Scheme {
	case "ws":
		req.URL.Scheme = "http"
	case "wss":
		req.URL.Scheme = "https"
	}

	if t, ok := ctx.Deadline(); ok {
		_ = hu.SetDeadline(t)
		defer func() {
			_ = hu.SetDeadline(time.Time{})
		}()
	}

	if err = req.Write(hu.Conn); err != nil {
		return err
	}

	reader := textproto.NewConn(hu.Conn)
	// First line: HTTP/1.1 101 Switching Protocols
	line, err := reader.ReadLine()
	if err != nil {
		return err
	}

	if !strings.Contains(line, "101 Switching Protocols") {
		return &net.ParseError{Type: "protocol", Text: "not a httpupgrade connection"}
	}

	header, err := reader.ReadMIMEHeader()
	if err != nil {
		return err
	}

	if !strings.EqualFold(header.Get("Upgrade"), "websocket") ||
		!strings.EqualFold(header.Get("Connection"), "upgrade") {
		return &net.ParseError{Type: "protocol", Text: "not a httpupgrade connection"}
	}

	hu.reader = reader.R
	return nil
}

// StreamHTTPUpgrade return a HTTPUpgrade conn
func StreamHTTPUpgrade(conn net.Conn, url string, requestHeader http.Header) (net.Conn, error) {
	huConn := &HTTPUpgrade{
		Conn: conn,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	ch := make(chan error)
	go func() {
		if err := huConn.handshake(ctx, url, requestHeader); err != nil {
			ch <- err
		}
		close(ch)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-ch:
		if err == nil {
			return huConn, nil
		}
		return nil, err
	}
}
