package process

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/Dreamacro/clash/common/byteorder"
)

const (
	sizeofSocketID      = 0x30
	sizeofSocketRequest = sizeofSocketID + 0x8
	sizeofSocket        = sizeofSocketID + 0x18
	pathProc            = "/proc"
)

var native = byteorder.Native

type socketRequest struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	pad      uint8
	States   uint32
	ID       netlink.SocketID
}

func (r *socketRequest) Serialize() []byte {
	b := writeBuffer{Bytes: make([]byte, sizeofSocketRequest)}
	b.Write(r.Family)
	b.Write(r.Protocol)
	b.Write(r.Ext)
	b.Write(r.pad)
	native.PutUint32(b.Next(4), r.States)
	binary.BigEndian.PutUint16(b.Next(2), r.ID.SourcePort)
	binary.BigEndian.PutUint16(b.Next(2), r.ID.DestinationPort)
	if r.Family == unix.AF_INET6 {
		copy(b.Next(16), r.ID.Source)
		copy(b.Next(16), r.ID.Destination)
	} else {
		copy(b.Next(4), r.ID.Source.To4())
		b.Next(12)
		copy(b.Next(4), r.ID.Destination.To4())
		b.Next(12)
	}
	native.PutUint32(b.Next(4), r.ID.Interface)
	native.PutUint32(b.Next(4), r.ID.Cookie[0])
	native.PutUint32(b.Next(4), r.ID.Cookie[1])
	return b.Bytes
}

func (r *socketRequest) Len() int {
	return sizeofSocketRequest
}

type writeBuffer struct {
	Bytes []byte
	pos   int
}

func (b *writeBuffer) Write(c byte) {
	b.Bytes[b.pos] = c
	b.pos++
}

func (b *writeBuffer) Next(n int) []byte {
	s := b.Bytes[b.pos : b.pos+n]
	b.pos += n
	return s
}

func findProcessName(network string, ip netip.Addr, srcPort int) (string, error) {
	inode, uid, err := resolveSocketByNetlink(network, ip, srcPort)
	if err != nil {
		return "", err
	}

	return resolveProcessNameByProcSearch(inode, uid)
}

func resolveSocketByNetlink(network string, ip netip.Addr, srcPort int) (uint32, uint32, error) {
	request := &socketRequest{
		States: nl.TCPDIAG_NOCOOKIE,
	}

	if ip.Is4() {
		request.Family = unix.AF_INET
	} else {
		request.Family = unix.AF_INET6
	}

	if strings.HasPrefix(network, "tcp") {
		request.Protocol = unix.IPPROTO_TCP
	} else if strings.HasPrefix(network, "udp") {
		request.Protocol = unix.IPPROTO_UDP
	} else {
		return 0, 0, ErrInvalidNetwork
	}

	request.ID = netlink.SocketID{
		SourcePort: uint16(srcPort),
		Source:     ip.AsSlice(),
		Cookie:     [2]uint32{nl.TCPDIAG_NOCOOKIE, nl.TCPDIAG_NOCOOKIE},
	}

	s, err := nl.Subscribe(unix.NETLINK_INET_DIAG)
	if err != nil {
		return 0, 0, err
	}
	defer s.Close()

	req := nl.NewNetlinkRequest(nl.SOCK_DIAG_BY_FAMILY, unix.NLM_F_DUMP)
	req.AddData(request)

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

func resolveProcessNameByProcSearch(inode, uid uint32) (string, error) {
	files, err := os.ReadDir(pathProc)
	if err != nil {
		return "", err
	}

	buffer := make([]byte, unix.PathMax)
	socket := fmt.Appendf(nil, "socket:[%d]", inode)

	for _, f := range files {
		if !f.IsDir() || !isPid(f.Name()) {
			continue
		}

		info, err := f.Info()
		if err != nil {
			return "", err
		}
		if info.Sys().(*syscall.Stat_t).Uid != uid {
			continue
		}

		processPath := filepath.Join(pathProc, f.Name())
		fdPath := filepath.Join(processPath, "fd")

		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			n, err := unix.Readlink(filepath.Join(fdPath, fd.Name()), buffer)
			if err != nil {
				continue
			}

			if bytes.Equal(buffer[:n], socket) {
				return os.Readlink(filepath.Join(processPath, "exe"))
			}
		}
	}

	return "", fmt.Errorf("process of uid(%d), inode(%d) not found", uid, inode)
}

func deserialize(b []byte) (uint32, uint32, error) {
	if len(b) < sizeofSocket {
		return 0, 0, fmt.Errorf("socket data short read (%d); want %d", len(b), sizeofSocket)
	}
	return native.Uint32(b[68:72]), native.Uint32(b[64:68]), nil
}

func isPid(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return !unicode.IsDigit(r)
	}) == -1
}
