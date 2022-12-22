package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	D "github.com/miekg/dns"
	"github.com/phuslu/log"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/common/picker"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"
)

var errProxyNotFound = errors.New("proxy adapter not found")

func putMsgToCache(c *cache.LruCache[string, *D.Msg], key string, msg *D.Msg) {
	if q := msg.Question[0]; q.Qtype == D.TypeTXT && strings.HasPrefix(q.Name, "_acme-challenge") {
		return
	}

	var ttl uint32
	switch {
	case len(msg.Answer) != 0:
		ttl = msg.Answer[0].Header().Ttl
	case len(msg.Ns) != 0:
		ttl = msg.Ns[0].Header().Ttl
	case len(msg.Extra) != 0:
		ttl = msg.Extra[0].Header().Ttl
	default:
		log.Debug().Str("msg", msg.String()).Msg("[DNS] response msg empty")
		return
	}

	c.SetWithExpire(key, msg.Copy(), time.Now().Add(time.Second*time.Duration(ttl)))
}

func setMsgTTL(msg *D.Msg, ttl uint32) {
	setMsgTTLWithForce(msg, ttl, true)
}

func setMsgTTLWithForce(msg *D.Msg, ttl uint32, force bool) {
	for _, answer := range msg.Answer {
		if !force && answer.Header().Ttl >= ttl {
			continue
		}
		answer.Header().Ttl = ttl
	}

	for _, ns := range msg.Ns {
		if !force && ns.Header().Ttl >= ttl {
			continue
		}
		ns.Header().Ttl = ttl
	}

	for _, extra := range msg.Extra {
		if !force && extra.Header().Ttl >= ttl {
			continue
		}
		extra.Header().Ttl = ttl
	}
}

func isIPRequest(q D.Question) bool {
	return q.Qclass == D.ClassINET && (q.Qtype == D.TypeA || q.Qtype == D.TypeAAAA)
}

func transform(servers []NameServer, resolver *Resolver) []dnsClient {
	var ret []dnsClient
	for _, s := range servers {
		switch s.Net {
		case "https":
			ret = append(ret, newDoHClient(s.Addr, resolver, s.ProxyAdapter))
			continue
		case "quic":
			ret = append(ret, newDoqClient(s.Addr, resolver, s.ProxyAdapter))
			continue
		case "dhcp":
			ret = append(ret, newDHCPClient(s.Addr))
			continue
		}

		host, port, _ := net.SplitHostPort(s.Addr)
		var ip string
		if _, err := netip.ParseAddr(host); err == nil {
			ip = host
		}
		ret = append(ret, &client{
			Client: &D.Client{
				Net: s.Net,
				TLSConfig: &tls.Config{
					ServerName: host,
				},
				UDPSize: 4096,
				Timeout: 5 * time.Second,
			},
			port:         port,
			host:         host,
			iface:        s.Interface,
			r:            resolver,
			proxyAdapter: s.ProxyAdapter,
			isDHCP:       s.IsDHCP,
			ip:           ip,
		})
	}
	return ret
}

func handleMsgWithEmptyAnswer(r *D.Msg) *D.Msg {
	msg := &D.Msg{}
	msg.Answer = []D.RR{}

	msg.SetRcode(r, D.RcodeSuccess)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	return msg
}

func msgToIP(msg *D.Msg) []netip.Addr {
	var ips []netip.Addr

	for _, answer := range msg.Answer {
		switch ans := answer.(type) {
		case *D.AAAA:
			ip, ok := netip.AddrFromSlice(ans.AAAA)
			if !ok {
				continue
			}
			ips = append(ips, ip)
		case *D.A:
			ip, ok := netip.AddrFromSlice(ans.A)
			if !ok {
				continue
			}
			ips = append(ips, ip)
		}
	}

	return ips
}

func msgToIPStr(msg *D.Msg) []string {
	var ips []string

	for _, answer := range msg.Answer {
		switch ans := answer.(type) {
		case *D.AAAA:
			if ans.AAAA == nil {
				continue
			}
			ips = append(ips, ans.AAAA.String())
		case *D.A:
			if ans.A == nil {
				continue
			}
			ips = append(ips, ans.A.String())
		}
	}

	return ips
}

type wrapPacketConn struct {
	net.PacketConn
	rAddr net.Addr
}

func (wpc *wrapPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = wpc.PacketConn.ReadFrom(b)
	return n, err
}

func (wpc *wrapPacketConn) Write(b []byte) (n int, err error) {
	return wpc.PacketConn.WriteTo(b, wpc.rAddr)
}

func (wpc *wrapPacketConn) RemoteAddr() net.Addr {
	return wpc.rAddr
}

func dialContextWithProxyAdapter(ctx context.Context, adapterName string, network string, dstIP netip.Addr, port string, opts ...dialer.Option) (net.Conn, error) {
	proxy, ok := tunnel.Proxies()[adapterName]
	if !ok {
		return nil, errProxyNotFound
	}

	networkType := C.TCP
	if network == "udp" {
		networkType = C.UDP
	}

	metadata := &C.Metadata{
		NetWork: networkType,
		Host:    "",
		DstIP:   dstIP,
		DstPort: port,
	}

	rawAdapter := fetchRawProxyAdapter(proxy.(*adapter.Proxy).ProxyAdapter, metadata)

	if networkType == C.UDP {
		if !rawAdapter.SupportUDP() {
			return nil, fmt.Errorf("proxy adapter [%s] UDP is not supported", rawAdapter.Name())
		}

		packetConn, err := rawAdapter.ListenPacketContext(ctx, metadata, opts...)
		if err != nil {
			return nil, err
		}

		return &wrapPacketConn{
			PacketConn: packetConn,
			rAddr:      metadata.UDPAddr(),
		}, nil
	}

	return rawAdapter.DialContext(ctx, metadata, opts...)
}

func fetchRawProxyAdapter(proxyAdapter C.ProxyAdapter, metadata *C.Metadata) C.ProxyAdapter {
	if p := proxyAdapter.Unwrap(metadata); p != nil {
		return fetchRawProxyAdapter(p.(*adapter.Proxy).ProxyAdapter, metadata)
	}

	return proxyAdapter
}

func batchExchange(ctx context.Context, clients []dnsClient, m *D.Msg) (msg *D.Msg, err error) {
	fast, ctx := picker.WithContext[*D.Msg](ctx)
	for _, clientM := range clients {
		r := clientM
		fast.Go(func() (*D.Msg, error) {
			mm, fErr := r.ExchangeContext(ctx, m)
			if fErr != nil {
				return nil, fErr
			} else if mm.Rcode == D.RcodeServerFailure || mm.Rcode == D.RcodeRefused {
				return nil, errors.New("server failure")
			}
			return mm, nil
		})
	}

	elm := fast.Wait()
	if elm == nil {
		err = errors.New("all DNS requests failed")
		if fErr := fast.Error(); fErr != nil {
			err = fmt.Errorf("%w, first error: %s", err, fErr.Error())
		}
		return nil, err
	}

	return elm, nil
}

func logDnsResponse(q D.Question, msg *D.Msg, network, source, proxyAdapter string) {
	if msg == nil || (q.Qtype != D.TypeA && q.Qtype != D.TypeAAAA) {
		return
	}

	var pr string
	if network != "" {
		network = network + "://"
	}
	if proxyAdapter != "" {
		pr = "(" + proxyAdapter + ")"
	}
	log.Debug().
		Str("source", fmt.Sprintf("%s%s%s", network, source, pr)).
		Str("qType", D.Type(q.Qtype).String()).
		Str("name", q.Name).
		Strs("answer", msgToIPStr(msg)).
		Msg("[DNS] dns response")
}
