package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	D "github.com/miekg/dns"
	"github.com/phuslu/log"
	"github.com/quic-go/quic-go/http3"
	"github.com/samber/lo"

	"github.com/yaling888/quirktiva/common/cache"
	"github.com/yaling888/quirktiva/common/errors2"
	"github.com/yaling888/quirktiva/common/picker"
	"github.com/yaling888/quirktiva/component/dialer"
	"github.com/yaling888/quirktiva/component/resolver"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/tunnel"
)

const (
	proxyKey     = contextKey("key-dns-client-proxy")
	proxyTimeout = 10 * time.Second
)

func putMsgToCache(c *cache.LruCache[string, *rMsg], key string, msg *rMsg) {
	putMsgToCacheWithExpire(c, key, msg, 0)
}

func putMsgToCacheWithExpire(c *cache.LruCache[string, *rMsg], key string, msg *rMsg, sec uint32) {
	if sec == 0 {
		if sec = minTTL(msg.Msg.Answer); sec == 0 {
			if sec = minTTL(msg.Msg.Ns); sec == 0 {
				sec = minTTL(msg.Msg.Extra)
			}
		}
		if sec == 0 {
			return
		}
		if !msg.Lan {
			sec = max(sec, 300) // at least 5 minutes to cache
		}
	}

	sortAnswer(msg.Msg.Answer)

	c.SetWithExpire(key, msg.Copy(), time.Now().Add(time.Duration(sec)*time.Second))
}

func setMsgTTL(msg *D.Msg, ttl uint32) {
	setMsgTTLWithForce(msg, ttl, true)
}

func setMsgMaxTTL(msg *D.Msg, ttl uint32) {
	setMsgTTLWithForce(msg, ttl, false)
}

func setMsgTTLWithForce(msg *D.Msg, ttl uint32, force bool) {
	setTTL(msg.Answer, ttl, force)
	setTTL(msg.Ns, ttl, force)
	setTTL(msg.Extra, ttl, force)
}

func setTTL(records []D.RR, ttl uint32, force bool) {
	if force {
		for i := range records {
			if records[i].Header().Rrtype != D.TypeA &&
				records[i].Header().Rrtype != D.TypeAAAA &&
				records[i].Header().Ttl == 0 {
				continue
			}
			records[i].Header().Ttl = ttl
		}
		return
	}

	delta := minTTL(records) - ttl
	for i := range records {
		if records[i].Header().Rrtype != D.TypeA &&
			records[i].Header().Rrtype != D.TypeAAAA &&
			records[i].Header().Ttl == 0 {
			continue
		}
		records[i].Header().Ttl = min(max(records[i].Header().Ttl-delta, 1), records[i].Header().Ttl)
	}
}

func minTTL(records []D.RR) uint32 {
	minObj := lo.MinBy(records, func(r1 D.RR, r2 D.RR) bool {
		return r1.Header().Ttl < r2.Header().Ttl
	})
	if minObj != nil {
		return minObj.Header().Ttl
	}
	return 0
}

func sortAnswer(answer []D.RR) {
	slices.SortFunc(answer, func(ip1, ip2 D.RR) int {
		var (
			addr1, addr2 netip.Addr
			ok           bool
		)
		switch a := ip1.(type) {
		case *D.A:
			addr1, ok = netip.AddrFromSlice(a.A.To4())
		case *D.AAAA:
			addr1, ok = netip.AddrFromSlice(a.AAAA)
		}
		if !ok {
			addr1 = netip.MustParseAddr("ffff::")
		}
		ok = false
		switch a := ip2.(type) {
		case *D.A:
			addr2, ok = netip.AddrFromSlice(a.A.To4())
		case *D.AAAA:
			addr2, ok = netip.AddrFromSlice(a.AAAA)
		}
		if !ok {
			addr2 = netip.MustParseAddr("ffff::")
		}
		return addr1.Compare(addr2)
	})
}

func isIPRequest(q D.Question) bool {
	return q.Qclass == D.ClassINET && (q.Qtype == D.TypeA || q.Qtype == D.TypeAAAA)
}

func transform(servers []NameServer, r *Resolver) []dnsClient {
	var ret []dnsClient
	for _, s := range servers {
		switch s.Net {
		case "https":
			ret = append(ret, newDoHClient(s.Addr, s.Proxy, false, r))
			continue
		case "http3":
			ret = append(ret, newDoHClient(s.Addr, s.Proxy, true, r))
			continue
		case "dhcp":
			ret = append(ret, newDHCPClient(s.Addr))
			continue
		}

		ret = append(ret, newClient(s.Net, s.Addr, s.Proxy, s.Interface, s.IsDHCP, r))
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
			ip, ok := netip.AddrFromSlice(ans.A.To4())
			if !ok {
				continue
			}
			ips = append(ips, ip)
		}
	}

	return ips
}

func msgToIPStr(msg D.Msg) []string {
	var ips []string

	for _, answer := range msg.Answer {
		switch ans := answer.(type) {
		case *D.AAAA:
			ips = append(ips, ans.AAAA.String())
		case *D.A:
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

func dialContextByProxyOrInterface(
	ctx context.Context,
	network string,
	dstIP netip.Addr,
	port string,
	proxyOrInterface string,
	opts ...dialer.Option,
) (net.Conn, error) {
	proxy, ok := tunnel.FindProxyByName(proxyOrInterface)
	if !ok {
		opts = []dialer.Option{dialer.WithInterface(proxyOrInterface), dialer.WithRoutingMark(0)}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(dstIP.String(), port), opts...)
		if err == nil {
			return conn, nil
		}
		return nil, fmt.Errorf("proxy %s not found, %w", proxyOrInterface, err)
	}

	networkType := C.TCP
	if network == "udp" {
		networkType = C.UDP
	}

	p, _ := strconv.ParseUint(port, 10, 16)
	metadata := &C.Metadata{
		NetWork: networkType,
		Host:    "",
		DstIP:   dstIP,
		DstPort: C.Port(p),
	}

	if networkType == C.UDP {
		if !proxy.SupportUDP() {
			if tunnel.UDPFallbackMatch.Load() {
				return nil, fmt.Errorf("proxy %s UDP is not supported", proxy.Name())
			} else {
				log.Debug().
					Str("proxy", proxy.Name()).
					Msg("[DNS] proxy UDP is not supported, fallback to TCP")

				metadata.NetWork = C.TCP
				goto tcp
			}
		}

		packetConn, err := proxy.ListenPacketContext(ctx, metadata, opts...)
		if err != nil {
			return nil, err
		}

		return &wrapPacketConn{
			PacketConn: packetConn,
			rAddr:      metadata.UDPAddr(),
		}, nil
	}

tcp:
	return proxy.DialContext(ctx, metadata, opts...)
}

func batchExchange(ctx context.Context, clients []dnsClient, m *D.Msg) (msg *rMsg, err error) {
	var (
		fast *picker.Picker[*rMsg]
		cs   = clients
	)

	if _, ok := ctx.Deadline(); ok {
		fast, ctx = picker.WithContext[*rMsg](ctx)
	} else {
		fast, ctx = picker.WithTimeout[*rMsg](ctx, resolver.DefaultDNSTimeout)
	}

	for i := range cs {
		r := cs[i]
		fast.Go(func() (*rMsg, error) {
			mm, fErr := r.ExchangeContext(ctx, m)
			go logDnsResponse(m.Question[0], mm, fErr)
			if fErr != nil {
				return nil, fErr
			} else if mm.Msg.Rcode == D.RcodeServerFailure || mm.Msg.Rcode == D.RcodeRefused {
				return nil, errors.New("server failure")
			}
			return mm, nil
		})
	}

	elm := fast.Wait()
	if elm == nil {
		err = errors.New("all DNS requests failed")
		if fErr := fast.Error(); fErr != nil {
			err = errors.Join(err, fErr)
		}
		return nil, errors2.Cause(err)
	}

	return elm, nil
}

func genMsgCacheKey(ctx context.Context, q D.Question) string {
	if proxy, ok := resolver.GetProxy(ctx); ok && proxy != "" {
		return fmt.Sprintf("%s:%s:%d:%d", proxy, q.Name, q.Qtype, q.Qclass)
	}
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qtype, q.Qclass)
}

func getTCPConn(ctx context.Context, addr string) (conn net.Conn, err error) {
	if proxy, ok := ctx.Value(proxyKey).(string); ok {
		host, port, _ := net.SplitHostPort(addr)
		ip, err1 := netip.ParseAddr(host)
		if err1 != nil {
			return nil, err1
		}
		conn, err = dialContextByProxyOrInterface(ctx, "tcp", ip, port, proxy)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err == nil {
		if c, ok := conn.(*net.TCPConn); ok {
			_ = c.SetKeepAlive(true)
		}
	}
	return
}

var _ net.PacketConn = (*quicConn)(nil)

type quicConn struct {
	net.PacketConn
}

func listenContextByProxyOrInterface(
	ctx context.Context,
	dstIP netip.Addr,
	port uint16,
	proxyOrInterface string,
	forceHTTP3 bool,
) (net.PacketConn, error) {
	proxy, ok := tunnel.FindProxyByName(proxyOrInterface)
	if !ok {
		opts := []dialer.Option{dialer.WithInterface(proxyOrInterface), dialer.WithRoutingMark(0)}
		conn, err := dialer.ListenPacket(ctx, "udp", "", opts...)
		if err == nil {
			return conn, nil
		}
		return nil, fmt.Errorf("proxy %s not found, %w", proxyOrInterface, err)
	}

	if !forceHTTP3 {
		return nil, fmt.Errorf("http3 transport proxy is disabled")
	}

	metadata := &C.Metadata{
		NetWork: C.UDP,
		Host:    "",
		DstIP:   dstIP,
		DstPort: C.Port(port),
	}

	packetConn, err := proxy.ListenPacketContext(ctx, metadata)
	if err != nil {
		return nil, err
	}

	return &quicConn{PacketConn: packetConn}, nil
}

func getPacketConn(ctx context.Context, ip netip.Addr, port uint16, proxy string, forceHTTP3 bool) (net.PacketConn, error) {
	if proxy == "" {
		return dialer.ListenPacket(ctx, "udp", "")
	}
	return listenContextByProxyOrInterface(ctx, ip, port, proxy, forceHTTP3)
}

func logDnsResponse(q D.Question, msg *rMsg, err error) {
	if msg == nil {
		return
	}
	if q.Qtype != D.TypeA && q.Qtype != D.TypeAAAA {
		return
	}

	if err != nil {
		if e := log.Debug(); e != nil {
			var http3Err *http3.Error
			if !errors.Is(err, context.Canceled) &&
				!(errors.As(err, &http3Err) && http3Err.ErrorCode == http3.ErrCodeRequestCanceled) {
				e.
					Err(err).
					Str("source", msg.Source).
					Str("qType", D.Type(q.Qtype).String()).
					Str("name", q.Name).
					Msg("[DNS] dns response failed")
			}
		}
		return
	}

	if e := log.Debug(); e != nil && msg.Msg != nil {
		e.
			Str("source", msg.Source).
			Str("qType", D.Type(q.Qtype).String()).
			Str("name", q.Name).
			EmbedObject(LogAnswer{ans: *msg.Msg}).
			Uint32("ttl", minTTL(msg.Msg.Answer)).
			Msg("[DNS] dns response")
	}
}

type LogAnswer struct {
	ans D.Msg
}

func (l LogAnswer) MarshalObject(e *log.Entry) {
	e.Strs("answer", msgToIPStr(l.ans))
}
