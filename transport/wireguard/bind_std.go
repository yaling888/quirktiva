//go:build !nogvisor

package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	_ "unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	wg "golang.zx2c4.com/wireguard/conn"
)

//go:linkname getSrcFromControl golang.zx2c4.com/wireguard/conn.getSrcFromControl
func getSrcFromControl(control []byte, ep *wg.StdNetEndpoint)

//go:linkname setSrcControl golang.zx2c4.com/wireguard/conn.setSrcControl
func setSrcControl(control *[]byte, ep *wg.StdNetEndpoint)

//go:linkname getGSOSize golang.zx2c4.com/wireguard/conn.getGSOSize
func getGSOSize(control []byte) (int, error)

//go:linkname setGSOSize golang.zx2c4.com/wireguard/conn.setGSOSize
func setGSOSize(control *[]byte, gsoSize uint16)

//go:linkname supportsUDPOffload golang.zx2c4.com/wireguard/conn.supportsUDPOffload
func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool)

//go:linkname errShouldDisableUDPGSO golang.zx2c4.com/wireguard/conn.errShouldDisableUDPGSO
func errShouldDisableUDPGSO(err error) bool

//go:linkname coalesceMessages golang.zx2c4.com/wireguard/conn.coalesceMessages
func coalesceMessages(addr *net.UDPAddr, ep *wg.StdNetEndpoint, bufs [][]byte, msgs []ipv6.Message, setGSO setGSOFunc) int

//go:linkname splitCoalescedMessages golang.zx2c4.com/wireguard/conn.splitCoalescedMessages
func splitCoalescedMessages(msgs []ipv6.Message, firstMsgAt int, getGSO getGSOFunc) (n int, err error)

const udpSegmentMaxDatagrams = 64 // This is a hard limit imposed by the kernel.

type setGSOFunc func(control *[]byte, gsoSize uint16)

type getGSOFunc func(control []byte) (int, error)

var _ wg.Bind = (*StdNetBind)(nil)

type StdNetBind struct {
	mu            sync.Mutex // protects all fields except as specified
	ipv4          *net.UDPConn
	ipv6          *net.UDPConn
	ipv4PC        *ipv4.PacketConn // will be nil on non-Linux
	ipv6PC        *ipv6.PacketConn // will be nil on non-Linux
	ipv4TxOffload bool
	ipv4RxOffload bool
	ipv6TxOffload bool
	ipv6RxOffload bool

	// these two fields are not guarded by mu
	udpAddrPool sync.Pool
	msgsPool    sync.Pool

	blackhole4 bool
	blackhole6 bool

	controlFns    []func(network, address string, c syscall.RawConn) error
	interfaceName string
	reserved      []byte
}

func (s *StdNetBind) setReserved(b []byte) {
	if len(b) < 4 || s.reserved == nil {
		return
	}
	b[1] = s.reserved[0]
	b[2] = s.reserved[1]
	b[3] = s.reserved[2]
}

func (s *StdNetBind) resetReserved(b []byte) {
	if len(b) < 4 {
		return
	}
	b[1] = 0x00
	b[2] = 0x00
	b[3] = 0x00
}

func (s *StdNetBind) listenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			for _, fn := range s.controlFns {
				if err := fn(network, address, c); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func (s *StdNetBind) listenNet(network string, port int) (*net.UDPConn, int, error) {
	listenIP, err := getListenIP(network, s.interfaceName)
	if err != nil {
		return nil, 0, err
	}

	conn, err := s.listenConfig().ListenPacket(context.Background(), network, listenIP+":"+strconv.Itoa(port))
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn.(*net.UDPConn), uaddr.Port, nil
}

func (s *StdNetBind) SetMark(mark uint32) error {
	return nil
}

func (*StdNetBind) ParseEndpoint(s string) (wg.Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &wg.StdNetEndpoint{
		AddrPort: e,
	}, nil
}

func (s *StdNetBind) UpdateControlFns(controlFns []func(network, address string, c syscall.RawConn) error) {
	s.controlFns = controlFns
}

func NewStdNetBind(
	controlFns []func(network, address string, c syscall.RawConn) error,
	interfaceName string,
	reserved []byte,
) wg.Bind {
	return &StdNetBind{
		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},

		msgsPool: sync.Pool{
			New: func() any {
				// ipv6.Message and ipv4.Message are interchangeable as they are
				// both aliases for x/net/internal/socket.Message.
				msgs := make([]ipv6.Message, wg.IdealBatchSize)
				for i := range msgs {
					msgs[i].Buffers = make(net.Buffers, 1)
					msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
				}
				return &msgs
			},
		},

		controlFns:    controlFns,
		interfaceName: interfaceName,
		reserved:      reserved,
	}
}

func (s *StdNetBind) Open(uport uint16) ([]wg.ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	var tries int

	if s.ipv4 != nil || s.ipv6 != nil {
		return nil, 0, wg.ErrBindAlreadyOpen
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var v4conn, v6conn *net.UDPConn
	var v4pc *ipv4.PacketConn
	var v6pc *ipv6.PacketConn

	v4conn, port, err = s.listenNet("udp4", port)
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		return nil, 0, err
	}

	// Listen on the same port as we're using for ipv4.
	v6conn, port, err = s.listenNet("udp6", port)
	if uport == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
		v4conn.Close()
		tries++
		goto again
	}
	if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
		v4conn.Close()
		return nil, 0, err
	}
	var fns []wg.ReceiveFunc
	if v4conn != nil {
		s.ipv4TxOffload, s.ipv4RxOffload = supportsUDPOffload(v4conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v4pc = ipv4.NewPacketConn(v4conn)
			s.ipv4PC = v4pc
		}
		fns = append(fns, s.makeReceiveIPv4(v4pc, v4conn, s.ipv4RxOffload))
		s.ipv4 = v4conn
	}
	if v6conn != nil {
		s.ipv6TxOffload, s.ipv6RxOffload = supportsUDPOffload(v6conn)
		if runtime.GOOS == "linux" || runtime.GOOS == "android" {
			v6pc = ipv6.NewPacketConn(v6conn)
			s.ipv6PC = v6pc
		}
		fns = append(fns, s.makeReceiveIPv6(v6pc, v6conn, s.ipv6RxOffload))
		s.ipv6 = v6conn
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}

	return fns, uint16(port), nil
}

func (s *StdNetBind) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers, OOB: (*msgs)[i].OOB}
	}
	s.msgsPool.Put(msgs)
}

func (s *StdNetBind) getMessages() *[]ipv6.Message {
	return s.msgsPool.Get().(*[]ipv6.Message)
}

var _ ipv6.Message = ipv4.Message{} // If compilation fails here these are no longer the same underlying type.

type batchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type batchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

func (s *StdNetBind) receiveIP(
	br batchReader,
	conn *net.UDPConn,
	rxOffload bool,
	bufs [][]byte,
	sizes []int,
	eps []wg.Endpoint,
) (numMsgs int, err error) {
	msgs := s.getMessages()
	for i := range bufs {
		(*msgs)[i].Buffers[0] = bufs[i]
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}
	defer s.putMessages(msgs)
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		if rxOffload {
			readAt := len(*msgs) - (wg.IdealBatchSize / udpSegmentMaxDatagrams)
			numMsgs, err = br.ReadBatch((*msgs)[readAt:], 0)
			if err != nil {
				return 0, err
			}
			numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
			if err != nil {
				return 0, err
			}
		} else {
			numMsgs, err = br.ReadBatch(*msgs, 0)
			if err != nil {
				return 0, err
			}
		}
	} else {
		msg := &(*msgs)[0]
		msg.N, msg.NN, _, msg.Addr, err = conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
		if err != nil {
			return 0, err
		}
		numMsgs = 1
	}
	for i := 0; i < numMsgs; i++ {
		msg := &(*msgs)[i]
		sizes[i] = msg.N
		if sizes[i] == 0 {
			continue
		}
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
		ep := &wg.StdNetEndpoint{AddrPort: addrPort} // TODO: remove allocation
		getSrcFromControl(msg.OOB[:msg.NN], ep)
		eps[i] = ep
		s.resetReserved(msg.Buffers[0])
	}
	return numMsgs, nil
}

func (s *StdNetBind) makeReceiveIPv4(pc *ipv4.PacketConn, conn *net.UDPConn, rxOffload bool) wg.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []wg.Endpoint) (n int, err error) {
		return s.receiveIP(pc, conn, rxOffload, bufs, sizes, eps)
	}
}

func (s *StdNetBind) makeReceiveIPv6(pc *ipv6.PacketConn, conn *net.UDPConn, rxOffload bool) wg.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []wg.Endpoint) (n int, err error) {
		return s.receiveIP(pc, conn, rxOffload, bufs, sizes, eps)
	}
}

// TODO: When all Binds handle IdealBatchSize, remove this dynamic function and
// rename the IdealBatchSize constant to BatchSize.
func (s *StdNetBind) BatchSize() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return wg.IdealBatchSize
	}
	return 1
}

func (s *StdNetBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err1, err2 error
	if s.ipv4 != nil {
		err1 = s.ipv4.Close()
		s.ipv4 = nil
		s.ipv4PC = nil
	}
	if s.ipv6 != nil {
		err2 = s.ipv6.Close()
		s.ipv6 = nil
		s.ipv6PC = nil
	}
	s.blackhole4 = false
	s.blackhole6 = false
	s.ipv4TxOffload = false
	s.ipv4RxOffload = false
	s.ipv6TxOffload = false
	s.ipv6RxOffload = false
	if err1 != nil {
		return err1
	}
	return err2
}

func (s *StdNetBind) Send(bufs [][]byte, endpoint wg.Endpoint) error {
	s.mu.Lock()
	blackhole := s.blackhole4
	conn := s.ipv4
	offload := s.ipv4TxOffload
	br := batchWriter(s.ipv4PC)
	is6 := false
	if endpoint.DstIP().Is6() {
		blackhole = s.blackhole6
		conn = s.ipv6
		br = s.ipv6PC
		is6 = true
		offload = s.ipv6TxOffload
	}
	s.mu.Unlock()

	if blackhole {
		return nil
	}
	if conn == nil {
		return syscall.EAFNOSUPPORT
	}

	for i := range bufs {
		s.setReserved(bufs[i])
	}

	msgs := s.getMessages()
	defer s.putMessages(msgs)
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	defer s.udpAddrPool.Put(ua)
	if is6 {
		as16 := endpoint.DstIP().As16()
		copy(ua.IP, as16[:])
		ua.IP = ua.IP[:16]
	} else {
		as4 := endpoint.DstIP().As4()
		copy(ua.IP, as4[:])
		ua.IP = ua.IP[:4]
	}
	ua.Port = int(endpoint.(*wg.StdNetEndpoint).Port())
	var (
		retried bool
		err     error
	)
retry:
	if offload {
		n := coalesceMessages(ua, endpoint.(*wg.StdNetEndpoint), bufs, *msgs, setGSOSize)
		err = s.send(conn, br, (*msgs)[:n])
		if err != nil && offload && errShouldDisableUDPGSO(err) {
			offload = false
			s.mu.Lock()
			if is6 {
				s.ipv6TxOffload = false
			} else {
				s.ipv4TxOffload = false
			}
			s.mu.Unlock()
			retried = true
			goto retry
		}
	} else {
		for i := range bufs {
			(*msgs)[i].Addr = ua
			(*msgs)[i].Buffers[0] = bufs[i]
			setSrcControl(&(*msgs)[i].OOB, endpoint.(*wg.StdNetEndpoint))
		}
		err = s.send(conn, br, (*msgs)[:len(bufs)])
	}
	if retried {
		return wg.ErrUDPGSODisabled{RetryErr: fmt.Errorf("disabled UDP GSO on %s, %w", conn.LocalAddr().String(), err)}
	}
	return err
}

func (s *StdNetBind) send(conn *net.UDPConn, pc batchWriter, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		for {
			n, err = pc.WriteBatch(msgs[start:], 0)
			if err != nil || n == len(msgs[start:]) {
				break
			}
			start += n
		}
	} else {
		for _, msg := range msgs {
			_, _, err = conn.WriteMsgUDP(msg.Buffers[0], msg.OOB, msg.Addr.(*net.UDPAddr))
			if err != nil {
				break
			}
		}
	}
	return err
}
