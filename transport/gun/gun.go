package gun

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"go.uber.org/atomic"
	"golang.org/x/net/http2"

	"github.com/yaling888/quirktiva/common/pool"
	C "github.com/yaling888/quirktiva/constant"
)

var (
	ErrInvalidLength = errors.New("invalid length")

	defaultHeader = http.Header{
		"content-type": []string{"application/grpc"},
		"user-agent":   []string{"grpc-go/1.36.0"},
	}

	defaultALPN = []string{"h2", "http/1.1"}
)

type DialFn = func(network, addr string) (net.Conn, error)

var _ net.Conn = (*Conn)(nil)

type Conn struct {
	net.Conn
	clientConn *http2.ClientConn
	response   *http.Response
	request    *http.Request
	writer     *io.PipeWriter
	once       sync.Once
	close      *atomic.Bool
	err        error
	remain     int
	br         *bufio.Reader
}

type Config struct {
	ServiceName string
	Host        string
}

func (g *Conn) initRequest() {
	response, err := g.clientConn.RoundTrip(g.request)
	if err != nil {
		g.err = err
		_ = g.writer.Close()
		return
	}

	if !g.close.Load() {
		g.response = response
		g.br = bufio.NewReader(response.Body)
	} else {
		_ = response.Body.Close()
	}
}

func (g *Conn) Read(b []byte) (n int, err error) {
	g.once.Do(g.initRequest)
	if g.err != nil {
		return 0, g.err
	}

	if g.remain > 0 {
		size := g.remain
		if len(b) < size {
			size = len(b)
		}

		n, err = io.ReadFull(g.br, b[:size])
		g.remain -= n
		return
	} else if g.response == nil {
		return 0, net.ErrClosed
	}

	// 0x00 grpclength(uint32) 0x0A uleb128 payload
	_, err = g.br.Discard(6)
	if err != nil {
		return 0, err
	}

	protobufPayloadLen, err := binary.ReadUvarint(g.br)
	if err != nil {
		return 0, ErrInvalidLength
	}

	size := int(protobufPayloadLen)
	if len(b) < size {
		size = len(b)
	}

	n, err = io.ReadFull(g.br, b[:size])
	if err != nil {
		return
	}

	remain := int(protobufPayloadLen) - n
	if remain > 0 {
		g.remain = remain
	}

	return n, nil
}

const bufSize = pool.NetBufferSize + 16

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, bufSize)
		return &b
	},
}

func (g *Conn) Write(b []byte) (n int, err error) {
	n = len(b)

	bufP := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufP)

	varuintSize := binary.PutUvarint((*bufP)[6:], uint64(n))
	grpcPayloadLen := uint32(varuintSize + 1 + n)

	(*bufP)[0] = byte(0)
	(*bufP)[5] = byte(0x0A)
	binary.BigEndian.PutUint32((*bufP)[1:], grpcPayloadLen)

	t := 6 + varuintSize
	t1 := copy((*bufP)[t:], b)

	_, err = g.writer.Write((*bufP)[:t+t1])
	if err == io.ErrClosedPipe && g.err != nil {
		err = g.err
	}
	if n > t1 {
		n = t1
		if err == nil {
			err = io.ErrShortWrite
		}
	}
	return
}

func (g *Conn) Close() error {
	g.close.Store(true)
	if r := g.response; r != nil {
		_ = r.Body.Close()
	}

	_ = g.writer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := g.clientConn.Shutdown(ctx); err != nil {
		return err
	}

	return g.Conn.Close()
}

func NewHTTP2Client(dialFn DialFn, tlsConfig *tls.Config) *http2.Transport {
	dialFunc := func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		plainConn, err := dialFn(network, addr)
		if err != nil {
			return nil, err
		}

		cfg.NextProtos = defaultALPN

		cn := tls.Client(plainConn, cfg)
		if err = cn.HandshakeContext(ctx); err != nil {
			_ = plainConn.Close()
			return nil, err
		}
		state := cn.ConnectionState()
		if p := state.NegotiatedProtocol; p != http2.NextProtoTLS {
			_ = cn.Close()
			return nil, fmt.Errorf("http2: unexpected ALPN protocol %s, want %s", p, http2.NextProtoTLS)
		}
		return cn, nil
	}

	return &http2.Transport{
		DialTLSContext:     dialFunc,
		TLSClientConfig:    tlsConfig,
		AllowHTTP:          false,
		DisableCompression: true,
		PingTimeout:        0,
	}
}

func StreamGunWithTransport(transport *http2.Transport, cfg *Config) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	tlsConn, err := transport.DialTLSContext(ctx, "", "", transport.TLSClientConfig)
	if err != nil {
		return nil, err
	}

	clientConn, err := transport.NewClientConn(tlsConn)
	if err != nil {
		return nil, err
	}

	serviceName := "GunService"
	if cfg.ServiceName != "" {
		serviceName = cfg.ServiceName
	}

	reader, writer := io.Pipe()
	request := &http.Request{
		Method: http.MethodPost,
		Body:   reader,
		URL: &url.URL{
			Scheme: "https",
			Host:   cfg.Host,
			Path:   fmt.Sprintf("/%s/Tun", serviceName),
			// for unescape path
			Opaque: fmt.Sprintf("//%s/%s/Tun", cfg.Host, serviceName),
		},
		Proto:      "HTTP/2",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     defaultHeader,
	}

	conn := &Conn{
		Conn:       tlsConn,
		clientConn: clientConn,
		request:    request,
		writer:     writer,
		close:      atomic.NewBool(false),
	}

	go conn.once.Do(conn.initRequest)
	return conn, nil
}

func StreamGunWithConn(conn net.Conn, tlsConfig *tls.Config, cfg *Config) (net.Conn, error) {
	dialFn := func(_, _ string) (net.Conn, error) {
		return conn, nil
	}

	transport := NewHTTP2Client(dialFn, tlsConfig)
	return StreamGunWithTransport(transport, cfg)
}
