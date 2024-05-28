package process

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/yaling888/quirktiva/common/pool"
)

const (
	sizeofSocketID = 0x30
	sizeofSocket   = sizeofSocketID + 0x18
)

type socketRequest struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	pad      uint8
	States   uint32
	ID       netlink.SocketID
}

func (r *socketRequest) serialize(bp *pool.BufferWriter) {
	bp.PutUint8(r.Family)
	bp.PutUint8(r.Protocol)
	bp.PutUint8(r.Ext)
	bp.PutUint8(r.pad)
	bp.PutUint32(r.States)
	bp.PutUint16be(r.ID.SourcePort)
	bp.PutUint16be(r.ID.DestinationPort)
	if r.Family == unix.AF_INET6 {
		bp.PutIPv6(r.ID.Source)
		bp.PutIPv6(r.ID.Destination)
	} else {
		bp.PutIPv4(r.ID.Source)
		bp.Grow(12)
		bp.PutIPv4(r.ID.Destination)
		bp.Grow(12)
	}
	bp.PutUint32(r.ID.Interface)
	bp.PutUint32(r.ID.Cookie[0])
	bp.PutUint32(r.ID.Cookie[1])
}

func findProcessPath(network string, from netip.AddrPort, to netip.AddrPort) (string, error) {
	inode, uid, err := resolveSocketByNetlink(network, from, to)
	if err != nil {
		return "", err
	}

	return resolveProcessPathByProcSearch(inode, uid)
}

func resolveSocketByNetlink(network string, from netip.AddrPort, to netip.AddrPort) (inode uint32, uid uint32, err error) {
	var families []byte
	if from.Addr().Unmap().Is4() {
		families = []byte{unix.AF_INET, unix.AF_INET6}
	} else {
		families = []byte{unix.AF_INET6, unix.AF_INET}
	}

	var protocol byte
	switch network {
	case TCP:
		protocol = unix.IPPROTO_TCP
	case UDP:
		protocol = unix.IPPROTO_UDP
	default:
		return 0, 0, ErrInvalidNetwork
	}

	if protocol == unix.IPPROTO_UDP {
		from, to = to, from
	}

	for _, family := range families {
		inode, uid, err = resolveSocketByNetlinkExact(family, protocol, from, to)
		if err == nil {
			return inode, uid, err
		}
	}

	return 0, 0, ErrNotFound
}

func resolveSocketByNetlinkExact(family byte, protocol byte, fromAddr netip.AddrPort, toAddr netip.AddrPort) (uint32, uint32, error) {
	var (
		fromIP net.IP
		toIP   net.IP
	)
	if family == unix.AF_INET {
		fromIP = net.IP(fromAddr.Addr().AsSlice()).To4()
		toIP = net.IP(toAddr.Addr().AsSlice()).To4()
	} else {
		fromIP = net.IP(fromAddr.Addr().AsSlice()).To16()
		toIP = net.IP(toAddr.Addr().AsSlice()).To16()
	}

	s, err := nl.Subscribe(unix.NETLINK_INET_DIAG)
	if err != nil {
		return 0, 0, err
	}
	defer s.Close()

	bufP := pool.GetBufferWriter()
	defer pool.PutBufferWriter(bufP)

	request := &socketRequest{
		Family:   family,
		Protocol: protocol,
		ID: netlink.SocketID{
			SourcePort:      fromAddr.Port(),
			DestinationPort: toAddr.Port(),
			Source:          fromIP,
			Destination:     toIP,
			Cookie:          [2]uint32{nl.TCPDIAG_NOCOOKIE, nl.TCPDIAG_NOCOOKIE},
		},
	}
	request.serialize(bufP)

	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, 0) // unix.NLM_F_DUMP
	req.AddRawData(bufP.Bytes())

	err = s.Send(req)
	if err != nil {
		return 0, 0, err
	}

	msgs, from, err := s.Receive()
	if err != nil {
		return 0, 0, err
	}

	if from.Pid != nl.PidKernel {
		return 0, 0, fmt.Errorf("wrong sender portid %d, expected %d", from.Pid, nl.PidKernel)
	}
	if len(msgs) == 0 {
		return 0, 0, fmt.Errorf("no message nor error from netlink")
	}
	if len(msgs) > 2 {
		return 0, 0, fmt.Errorf("multiple (%d) matching sockets", len(msgs))
	}

	inode, uid, err := deserialize(msgs[0].Data)
	if err != nil {
		return 0, 0, ErrNotFound
	}

	return inode, uid, nil
}

func resolveProcessPathByProcSearch(inode, uid uint32) (string, error) {
	const (
		path    = "/proc/"
		pathLen = len(path)
	)
	procDir, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func(procDir *os.File) {
		_ = procDir.Close()
	}(procDir)

	pids, err := procDir.Readdirnames(-1)
	if err != nil {
		return "", err
	}

	expectedSocketName := fmt.Appendf(nil, "socket:[%d]", inode)

	pathBuffer := pool.GetBufferWriter()
	defer pool.PutBufferWriter(pathBuffer)

	readlinkBuffer := pool.GetBufferWriter()
	readlinkBuffer.Grow(32)
	defer pool.PutBufferWriter(readlinkBuffer)

	pathBuffer.PutString(path)
	for _, pid := range pids {
		if !isPid(pid) {
			continue
		}

		pathBuffer.
			Truncate(pathLen).
			PutString(pid)

		stat := &unix.Stat_t{}
		err = unix.Stat(pathBuffer.String(), stat)
		if err != nil {
			continue
		} else if stat.Uid != uid {
			continue
		}

		pathBuffer.PutString("/fd/")
		fdsPrefixLength := pathBuffer.Len()

		fdDir, err := os.Open(pathBuffer.String())
		if err != nil {
			continue
		}

		fds, err := fdDir.Readdirnames(-1)
		_ = fdDir.Close()
		if err != nil {
			continue
		}

		for _, fd := range fds {
			pathBuffer.
				Truncate(fdsPrefixLength).
				PutString(fd)

			n, err := unix.Readlink(pathBuffer.String(), *readlinkBuffer)
			if err != nil {
				continue
			}

			if bytes.Equal((*readlinkBuffer)[:n], expectedSocketName) {
				return os.Readlink(path + pid + "/exe")
			}
		}
	}

	return "", fmt.Errorf("inode %d of uid %d not found", inode, uid)
}

func isPid(name string) bool {
	for _, c := range name {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

func deserialize(b []byte) (inode, uid uint32, err error) {
	if len(b) < sizeofSocket {
		return 0, 0, fmt.Errorf("socket data short read (%d); want %d", len(b), sizeofSocket)
	}
	buf := pool.BufferReader(b)
	buf.Skip(64)
	uid = buf.ReadUint32()
	inode = buf.ReadUint32()
	return
}
