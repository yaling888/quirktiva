package inbound

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/yaling888/quirktiva/common/util"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/transport/socks5"
)

func parseSocksAddr(target socks5.Addr) *C.Metadata {
	metadata := &C.Metadata{}

	switch target[0] {
	case socks5.AtypDomainName:
		// trim for FQDN
		metadata.Host = strings.TrimSuffix(string(target[2:2+target[1]]), ".")
		metadata.DstPort = C.Port((int(target[2+target[1]]) << 8) | int(target[2+target[1]+1]))
	case socks5.AtypIPv4:
		metadata.DstIP, _ = netip.AddrFromSlice(target[1 : 1+net.IPv4len])
		metadata.DstPort = C.Port((int(target[1+net.IPv4len]) << 8) | int(target[1+net.IPv4len+1]))
	case socks5.AtypIPv6:
		ip6, _ := netip.AddrFromSlice(target[1 : 1+net.IPv6len])
		metadata.DstIP = ip6.Unmap()
		metadata.DstPort = C.Port((int(target[1+net.IPv6len]) << 8) | int(target[1+net.IPv6len+1]))
	}

	return metadata
}

func parseHTTPAddr(request *http.Request) *C.Metadata {
	host := request.URL.Hostname()
	port, _ := strconv.ParseUint(util.EmptyOr(request.URL.Port(), "80"), 10, 16)

	// trim FQDN (#737)
	host = strings.TrimSuffix(host, ".")

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Host:    host,
		DstIP:   netip.Addr{},
		DstPort: C.Port(port),
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		metadata.DstIP = ip
	}

	return metadata
}

func parseAddr(addr net.Addr) (netip.Addr, int, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip.Unmap(), a.Port, nil
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return ip.Unmap(), a.Port, nil
	default:
		return netip.Addr{}, 0, fmt.Errorf("unknown address type %T", addr)
	}
}
