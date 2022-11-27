package wireguard

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

type wgDialer interface {
	DialContext(context.Context, string, netip.AddrPort) (net.Conn, error)
	ListenPacket(context.Context, netip.AddrPort) (net.PacketConn, error)
}

var _ conn.Bind = (*WgBind)(nil)

type WgBind struct {
	ctx      context.Context
	dialer   wgDialer
	endpoint conn.StdNetEndpoint
	conn     *wgConn
	connMux  sync.Mutex
	done     chan struct{}
}

func (c *WgBind) connect() (*wgConn, error) {
	serverConn := c.conn
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}

	c.connMux.Lock()
	defer c.connMux.Unlock()

	serverConn = c.conn
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}

	udpConn, err := c.dialer.DialContext(c.ctx, "udp", (netip.AddrPort)(c.endpoint))
	if err != nil {
		return nil, &wgError{err}
	}
	c.conn = &wgConn{
		Conn: udpConn,
		done: make(chan struct{}),
	}
	return c.conn, nil
}

func (c *WgBind) Open(_ uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	select {
	case <-c.done:
		err = net.ErrClosed
		return
	default:
	}
	return []conn.ReceiveFunc{c.receive}, 0, nil
}

func (c *WgBind) receive(b []byte) (n int, ep conn.Endpoint, err error) {
	udpConn, err := c.connect()
	if err != nil {
		err = &wgError{err}
		return
	}

	n, err = udpConn.Read(b)
	if err != nil {
		_ = udpConn.Close()
		select {
		case <-c.done:
		default:
			err = &wgError{err}
		}
		return
	}
	ep = c.endpoint
	return
}

func (c *WgBind) Reset() {
	c.connMux.Lock()
	defer c.connMux.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func (c *WgBind) Close() error {
	c.connMux.Lock()
	defer c.connMux.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	if c.done == nil {
		c.done = make(chan struct{})
		return nil
	}
	select {
	case <-c.done:
		return net.ErrClosed
	default:
		close(c.done)
	}
	return nil
}

func (c *WgBind) SetMark(_ uint32) error {
	return nil
}

func (c *WgBind) Send(b []byte, _ conn.Endpoint) error {
	udpConn, err := c.connect()
	if err != nil {
		return err
	}
	_, err = udpConn.Write(b)
	if err != nil {
		_ = udpConn.Close()
	}
	return err
}

func (c *WgBind) ParseEndpoint(_ string) (conn.Endpoint, error) {
	return c.endpoint, nil
}

func (c *WgBind) Endpoint() conn.Endpoint {
	return c.endpoint
}

func NewWgBind(ctx context.Context, dialer wgDialer, endpoint netip.AddrPort) *WgBind {
	return &WgBind{
		ctx:      ctx,
		dialer:   dialer,
		endpoint: conn.StdNetEndpoint(endpoint),
	}
}

type wgConn struct {
	net.Conn
	access sync.Mutex
	done   chan struct{}
}

func (w *wgConn) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	select {
	case <-w.done:
		return net.ErrClosed
	default:
	}
	_ = w.Conn.Close()
	close(w.done)
	return nil
}

type wgError struct {
	cause error
}

func (w *wgError) Error() string {
	return w.cause.Error()
}

func (w *wgError) Timeout() bool {
	if cause, causeNet := w.cause.(net.Error); causeNet {
		return cause.Timeout()
	}
	return false
}

func (w *wgError) Temporary() bool {
	return true
}
