package statistic

import (
	"errors"
	"net"

	"github.com/phuslu/log"
	"go.uber.org/atomic"

	"github.com/yaling888/clash/common/snifer/tls"
	"github.com/yaling888/clash/component/resolver"
	C "github.com/yaling888/clash/constant"
)

type tcpSniffer struct {
	C.Conn

	metadata    *C.Metadata
	firstPacket *atomic.Bool
	allowBreak  bool
}

func (ts *tcpSniffer) Write(b []byte) (int, error) {
	if ts.metadata.Host == "" && ts.firstPacket.CompareAndSwap(false, true) {
		host := ""
		switch ts.metadata.DstPort {
		case 80, 8080, 8880, 2052, 2082, 2086, 2095:
			host = tls.SniffHTTP(b)
		case 443, 8443, 2053, 2083, 2087, 2096, 5223, 993, 465, 995:
			host = tls.SniffTLS(b)
		}
		if tls.VerifyHostnameInSNI(host) {
			host = tls.ToLowerASCII(host)

			log.Debug().
				Str("host", host).
				NetIPAddr("ip", ts.metadata.DstIP).
				Msg("[Sniffer] update tls sni")

			resolver.InsertHostByIP(ts.metadata.DstIP, host)

			if ts.allowBreak {
				_ = ts.Conn.Close()
				return 0, errors.New("sni updated, break current link to avoid leaks")
			} else {
				ts.metadata.Host = host
			}
		}
	}

	return ts.Conn.Write(b)
}

func NewTCPSniffer(conn C.Conn, metadata *C.Metadata, allowBreak bool) C.Conn {
	return &tcpSniffer{
		Conn:        conn,
		metadata:    metadata,
		allowBreak:  allowBreak,
		firstPacket: atomic.NewBool(false),
	}
}

type udpSniffer struct {
	C.PacketConn

	metadata    *C.Metadata
	firstPacket *atomic.Bool
	allowBreak  bool
}

func (us *udpSniffer) WriteTo(b []byte, addr net.Addr) (int, error) {
	if us.metadata.Host == "" && us.firstPacket.CompareAndSwap(false, true) {
		host := ""
		switch us.metadata.DstPort {
		case 443, 8443, 2053, 2083, 2087, 2096, 5223:
			host = tls.SniffQUIC(b)
		}
		if tls.VerifyHostnameInSNI(host) {
			host = tls.ToLowerASCII(host)

			log.Debug().
				Str("host", host).
				NetIPAddr("ip", us.metadata.DstIP).
				Msg("[Sniffer] update quic sni")

			resolver.InsertHostByIP(us.metadata.DstIP, host)

			if us.allowBreak {
				_ = us.PacketConn.Close()
				return 0, errors.New("sni updated, break current link to avoid leaks")
			} else {
				us.metadata.Host = host
			}
		}
	}

	return us.PacketConn.WriteTo(b, addr)
}

func NewUDPSniffer(conn C.PacketConn, metadata *C.Metadata, allowBreak bool) C.PacketConn {
	return &udpSniffer{
		PacketConn:  conn,
		metadata:    metadata,
		allowBreak:  allowBreak,
		firstPacket: atomic.NewBool(false),
	}
}
