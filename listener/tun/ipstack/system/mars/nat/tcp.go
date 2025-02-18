package nat

import (
	"net"
	"net/netip"
	"time"
)

type TCP struct {
	listener *net.TCPListener
	portal4  netip.Addr
	portal6  netip.Addr
	table    *table
}

type conn struct {
	net.Conn

	tuple tuple
}

func (t *TCP) Accept() (net.Conn, error) {
	c, err := t.listener.AcceptTCP()
	if err != nil {
		return nil, err
	}

	addr := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	tup := t.table.tupleOf(addr.Port())
	if pt := addr.Addr().Unmap(); (pt != t.portal4 && pt != t.portal6) || tup == zeroTuple {
		_ = c.Close()
		return nil, &net.AddrError{Err: "invalid remote address", Addr: addr.String()}
	}

	addition(c)

	return &conn{
		Conn:  c,
		tuple: tup,
	}, nil
}

func (t *TCP) Close() error {
	return t.listener.Close()
}

func (t *TCP) Addr() net.Addr {
	return t.listener.Addr()
}

func (t *TCP) SetDeadline(time time.Time) error {
	return t.listener.SetDeadline(time)
}

func (c *conn) Close() error {
	return c.Conn.Close()
}

func (c *conn) LocalAddr() net.Addr {
	return net.TCPAddrFromAddrPort(c.tuple.SourceAddr)
}

func (c *conn) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(c.tuple.DestinationAddr)
}
