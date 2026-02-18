package mitm

import (
	"net"
	"sync"

	"github.com/yaling888/quirktiva/constant"
)

var _ net.Listener = (*mitmListener)(nil)

type mitmListener struct {
	addr   net.Addr
	connCh chan constant.ConnContext
	done   chan struct{}
	mux    sync.Mutex
}

func (l *mitmListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	default:
		select {
		case conn := <-l.connCh:
			c := conn.Conn()
			key := getMitmConnectionKey(c)
			metadata := new(constant.Metadata)
			*metadata = *conn.Metadata()
			inConnCtxMap.Store(key, &connCtx{metadata: metadata, close: c.Close})
			return c, nil
		case <-l.done:
			return nil, net.ErrClosed
		}
	}
}

func (l *mitmListener) Close() error {
	l.mux.Lock()
	defer l.mux.Unlock()
	select {
	case <-l.done:
		return net.ErrClosed
	default:
		close(l.done)
		<-l.done
		close(l.connCh)
		for conn := range l.connCh {
			_ = conn.Conn().Close()
		}
	}
	return nil
}

func (l *mitmListener) Addr() net.Addr {
	return l.addr
}

func (l *mitmListener) ConnIn() chan<- constant.ConnContext {
	return l.connCh
}

func newMitmListener() *mitmListener {
	return &mitmListener{
		addr: &net.TCPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		},
		connCh: make(chan constant.ConnContext, 128),
		done:   make(chan struct{}),
	}
}
