package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type wgDialer interface {
	DialContext(context.Context, string, netip.AddrPort) (net.Conn, error)
}

var _ conn.Bind = (*WgBind)(nil)

type WgBind struct {
	ctx      context.Context
	dialer   wgDialer
	endpoint conn.StdNetEndpoint
	reserved []byte
	conn     *wgConn
	connMux  sync.Mutex
	done     chan struct{}
}

func (wb *WgBind) connect() (*wgConn, error) {
	serverConn := wb.conn
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}

	wb.connMux.Lock()
	defer wb.connMux.Unlock()

	serverConn = wb.conn
	if serverConn != nil {
		select {
		case <-serverConn.done:
			serverConn = nil
		default:
			return serverConn, nil
		}
	}

	udpConn, err := wb.dialer.DialContext(wb.ctx, "udp", (netip.AddrPort)(wb.endpoint))
	if err != nil {
		return nil, &wgError{err}
	}
	wb.conn = &wgConn{
		Conn: udpConn,
		done: make(chan struct{}),
	}
	return wb.conn, nil
}

func (wb *WgBind) Open(_ uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	select {
	case <-wb.done:
		err = net.ErrClosed
		return
	default:
	}
	return []conn.ReceiveFunc{wb.receive}, 0, nil
}

func (wb *WgBind) receive(b []byte) (n int, ep conn.Endpoint, err error) {
	var udpConn *wgConn
	udpConn, err = wb.connect()
	if err != nil {
		select {
		case <-wb.done:
			err = net.ErrClosed
		default:
			err = nil
		}
		if wgErr, ok := err.(*wgError); ok && wgErr.IsError(syscall.ENETUNREACH) {
			time.Sleep(2 * time.Second)
		}
		return
	}

	n, err = udpConn.Read(b)
	if err != nil {
		_ = udpConn.Close()
		select {
		case <-wb.done:
			err = net.ErrClosed
			return
		default:
			n = 0
			err = nil
		}
		return
	}
	wb.resetReserved(b)
	ep = wb.endpoint
	return
}

func (wb *WgBind) Reset() {
	wb.connMux.Lock()
	defer wb.connMux.Unlock()
	if wb.conn != nil {
		_ = wb.conn.Close()
	}
}

func (wb *WgBind) Close() error {
	wb.connMux.Lock()
	defer wb.connMux.Unlock()
	if wb.conn != nil {
		_ = wb.conn.Close()
	}
	if wb.done == nil {
		wb.done = make(chan struct{})
		return nil
	}
	select {
	case <-wb.done:
		return net.ErrClosed
	default:
		close(wb.done)
	}
	return nil
}

func (wb *WgBind) SetMark(_ uint32) error {
	return nil
}

func (wb *WgBind) Send(b []byte, _ conn.Endpoint) error {
	udpConn, err := wb.connect()
	if err != nil {
		return err
	}
	wb.setReserved(b)
	_, err = udpConn.Write(b)
	if err != nil {
		_ = udpConn.Close()
	}
	return err
}

func (wb *WgBind) ParseEndpoint(_ string) (conn.Endpoint, error) {
	return wb.endpoint, nil
}

func (wb *WgBind) Endpoint() conn.Endpoint {
	return wb.endpoint
}

func (wb *WgBind) setReserved(b []byte) {
	if len(b) < 4 || wb.reserved == nil {
		return
	}
	b[1] = wb.reserved[0]
	b[2] = wb.reserved[1]
	b[3] = wb.reserved[2]
}

func (wb *WgBind) resetReserved(b []byte) {
	if len(b) < 4 {
		return
	}
	b[1] = 0x00
	b[2] = 0x00
	b[3] = 0x00
}

func NewWgBind(ctx context.Context, dialer wgDialer, endpoint netip.AddrPort, reserved []byte) *WgBind {
	return &WgBind{
		ctx:      ctx,
		dialer:   dialer,
		reserved: reserved,
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

func (w *wgError) IsError(target error) bool {
	return errors.Is(w.cause, target)
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
