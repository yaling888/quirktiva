package obfs

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/yaling888/quirktiva/common/convert"
	"github.com/yaling888/quirktiva/common/pool"
)

// HTTPObfs is shadowsocks http simple-obfs implementation
type HTTPObfs struct {
	net.Conn
	host          string
	port          string
	bufP          *[]byte
	offset        int
	firstRequest  bool
	firstResponse bool
	randomHost    bool
}

func (ho *HTTPObfs) Read(b []byte) (int, error) {
	if ho.bufP != nil {
		n := copy(b, (*ho.bufP)[ho.offset:])
		ho.offset += n
		if ho.offset == len(*ho.bufP) {
			pool.PutNetBuf(ho.bufP)
			ho.bufP = nil
		}
		return n, nil
	}

	if ho.firstResponse {
		bufP := pool.GetNetBuf()
		n, err := ho.Conn.Read(*bufP)
		if err != nil {
			pool.PutNetBuf(bufP)
			return 0, err
		}
		idx := bytes.Index((*bufP)[:n], []byte("\r\n\r\n"))
		if idx == -1 {
			pool.PutNetBuf(bufP)
			return 0, io.EOF
		}
		ho.firstResponse = false
		length := n - (idx + 4)
		n = copy(b, (*bufP)[idx+4:n])
		if length > n {
			*bufP = (*bufP)[:idx+4+length]
			ho.bufP = bufP
			ho.offset = idx + 4 + n
		} else {
			pool.PutNetBuf(bufP)
		}
		return n, nil
	}
	return ho.Conn.Read(b)
}

func (ho *HTTPObfs) Write(b []byte) (int, error) {
	if ho.firstRequest {
		if ho.randomHost {
			ho.host = convert.RandHost()
		}
		randBytes := make([]byte, 16)
		_, _ = rand.Read(randBytes)
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/", ho.host), bytes.NewBuffer(b[:]))
		req.Header.Set("User-Agent", convert.RandUserAgent())
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Host = ho.host
		if ho.port != "80" {
			req.Host = fmt.Sprintf("%s:%s", ho.host, ho.port)
		}
		req.Header.Set("Sec-WebSocket-Key", base64.URLEncoding.EncodeToString(randBytes))
		req.ContentLength = int64(len(b))
		err := req.Write(ho.Conn)
		ho.firstRequest = false
		return len(b), err
	}

	return ho.Conn.Write(b)
}

// NewHTTPObfs return a HTTPObfs
func NewHTTPObfs(conn net.Conn, host string, port string, randomHost bool) net.Conn {
	return &HTTPObfs{
		Conn:          conn,
		firstRequest:  true,
		firstResponse: true,
		host:          host,
		port:          port,
		randomHost:    randomHost,
	}
}
