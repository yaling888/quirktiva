package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	D "github.com/miekg/dns"
	"github.com/phuslu/log"
	"github.com/quic-go/quic-go/http3"
	"github.com/samber/lo"

	"github.com/yaling888/quirktiva/common/cache"
	"github.com/yaling888/quirktiva/common/context2"
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
	sortAnswer(msg.Msg.Answer)

	if sec == 0 {
		if sec = minTTL(msg.Msg.Answer); sec == 0 {
			if sec = minTTL(msg.Msg.Ns); sec == 0 {
				sec = minTTL(msg.Msg.Extra)
			}
		}
		if sec <= 1 {
			return
		}
		if !msg.Lan {
			sec = max(sec, 300) // at least 5 minutes to cache
		}
	}

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
				records[i].Header().Rrtype != D.TypeHTTPS &&
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
			records[i].Header().Rrtype != D.TypeHTTPS &&
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

var maxAddr = netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

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
			addr1 = maxAddr
		}
		ok = false
		switch a := ip2.(type) {
		case *D.A:
			addr2, ok = netip.AddrFromSlice(a.A.To4())
		case *D.AAAA:
			addr2, ok = netip.AddrFromSlice(a.AAAA)
		}
		if !ok {
			addr2 = maxAddr
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

func msgToECH(msg *D.Msg) []byte {
	for _, answer := range msg.Answer {
		switch ans := answer.(type) {
		case *D.HTTPS:
			for _, kv := range ans.Value {
				switch svc := kv.(type) {
				case *D.SVCBECHConfig:
					return svc.ECH
				}
			}
		}
	}
	return nil
}

func msgToLog(msg D.Msg) []string {
	var logs []string

	for _, answer := range msg.Answer {
		switch ans := answer.(type) {
		case *D.AAAA:
			logs = append(logs, ans.AAAA.String())
		case *D.A:
			logs = append(logs, ans.A.String())
		case *D.HTTPS:
			for _, kv := range ans.Value {
				switch svc := kv.(type) {
				case *D.SVCBECHConfig:
					logs = append(logs, svc.String())
				case *D.SVCBIPv4Hint:
					logs = append(logs, svc.String())
				case *D.SVCBIPv6Hint:
					logs = append(logs, svc.String())
				}
			}
		case *D.CNAME:
			logs = append(logs, ans.Target)
		case *D.DNAME:
			logs = append(logs, ans.Target)
		case *D.MX:
			logs = append(logs, ans.Mx)
		case *D.NS:
			logs = append(logs, ans.Ns)
		case *D.PTR:
			logs = append(logs, ans.Ptr)
		case *D.SPF:
			logs = append(logs, ans.Txt...)
		case *D.TXT:
			logs = append(logs, ans.Txt...)
		case *D.OPT:
			for _, o := range ans.Option {
				switch o.(type) {
				case *D.EDNS0_NSID:
					logs = append(logs, "NSID: "+o.String())
				case *D.EDNS0_SUBNET:
					logs = append(logs, "SUBNET: "+o.String())
				case *D.EDNS0_COOKIE:
					logs = append(logs, "COOKIE: "+o.String())
				case *D.EDNS0_EXPIRE:
					logs = append(logs, "EXPIRE: "+o.String())
				case *D.EDNS0_TCP_KEEPALIVE:
					logs = append(logs, "KEEPALIVE: "+o.String())
				case *D.EDNS0_UL:
					logs = append(logs, "UPDATE LEASE: "+o.String())
				case *D.EDNS0_LLQ:
					logs = append(logs, "LONG LIVED QUERIES: "+o.String())
				case *D.EDNS0_DAU:
					logs = append(logs, "DNSSEC ALGORITHM UNDERSTOOD: "+o.String())
				case *D.EDNS0_DHU:
					logs = append(logs, "DS HASH UNDERSTOOD: "+o.String())
				case *D.EDNS0_N3U:
					logs = append(logs, "NSEC3 HASH UNDERSTOOD: "+o.String())
				case *D.EDNS0_LOCAL:
					logs = append(logs, "LOCAL OPT: "+o.String())
				case *D.EDNS0_PADDING:
					logs = append(logs, "PADDING: "+o.String())
				case *D.EDNS0_EDE:
					logs = append(logs, "EDE: "+o.String())
				case *D.EDNS0_ESU:
					logs = append(logs, "ESU: "+o.String())
				case *D.EDNS0_REPORTING:
					logs = append(logs, "REPORT-CHANNEL: "+o.String())
				case *D.EDNS0_ZONEVERSION:
					logs = append(logs, "ZONEVERSION: "+o.String())
				}
			}
		}
	}

	return logs
}

type wrapPacketConn struct {
	net.PacketConn
	rAddr net.Addr
}

func (wpc *wrapPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = wpc.ReadFrom(b)
	return n, err
}

func (wpc *wrapPacketConn) Write(b []byte) (n int, err error) {
	return wpc.WriteTo(b, wpc.rAddr)
}

func (wpc *wrapPacketConn) RemoteAddr() net.Addr {
	return wpc.rAddr
}

func dialContextByProxyOrInterface(
	ctx context.Context,
	network string,
	addrPort netip.AddrPort,
	proxyOrInterface string,
	opts ...dialer.Option,
) (net.Conn, error) {
	proxy, ok := tunnel.FindProxyByName(proxyOrInterface)
	if !ok {
		opts = []dialer.Option{dialer.WithInterface(proxyOrInterface), dialer.WithRoutingMark(0)}
		conn, err := dialer.DialContextAddrPort(ctx, network, addrPort, opts...)
		if err == nil {
			return conn, nil
		}
		return nil, fmt.Errorf("proxy %s not found, %w", proxyOrInterface, err)
	}

	networkType := C.TCP
	if network == "udp" {
		networkType = C.UDP
	}

	metadata := &C.Metadata{
		NetWork: networkType,
		Host:    "",
		DstIP:   addrPort.Addr(),
		DstPort: C.Port(addrPort.Port()),
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

	fast, ctx = picker.WithCancelCause[*rMsg](ctx, context2.ManualCanceled)

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
			err = fmt.Errorf("%w: %w", err, fErr)
		}
		return nil, err
	}

	return elm, nil
}

func genMsgCacheKey(ctx context.Context, q D.Question) string {
	if proxy, ok := resolver.GetProxy(ctx); ok && proxy != "" {
		return fmt.Sprintf("%s:%s:%d:%d", proxy, q.Name, q.Qtype, q.Qclass)
	}
	return fmt.Sprintf("%s:%d:%d", q.Name, q.Qtype, q.Qclass)
}

func getTCPConn(ctx context.Context, addrPort netip.AddrPort) (conn net.Conn, err error) {
	if proxy, ok := ctx.Value(proxyKey).(string); ok {
		conn, err = dialContextByProxyOrInterface(ctx, "tcp", addrPort, proxy)
	} else {
		conn, err = dialer.DialContextAddrPort(ctx, "tcp", addrPort)
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
		network := "udp"
		if dstIP.Is4() {
			network = "udp4"
		}
		opts := []dialer.Option{dialer.WithInterface(proxyOrInterface), dialer.WithRoutingMark(0)}
		conn, err := dialer.ListenPacket(ctx, network, "", opts...)
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
		network := "udp"
		if ip.Is4() {
			network = "udp4"
		}
		return dialer.ListenPacket(ctx, network, "")
	}
	return listenContextByProxyOrInterface(ctx, ip, port, proxy, forceHTTP3)
}

func logDnsResponse(q D.Question, msg *rMsg, err error) {
	if msg == nil {
		return
	}

	if err != nil {
		if e := log.Debug(); e != nil {
			if http3Err, ok := errors.AsType[*http3.Error](err); ok && http3Err.ErrorCode == http3.ErrCodeRequestCanceled {
				e.
					Str("cause", "h3_request_cancelled").
					Str("source", msg.Source).
					Str("qType", D.Type(q.Qtype).String()).
					Str("name", q.Name).
					Msg("[DNS] dns request cancelled")
			} else if errors.Is(err, context.Canceled) {
				e.
					Str("cause", "context_canceled").
					Str("source", msg.Source).
					Str("qType", D.Type(q.Qtype).String()).
					Str("name", q.Name).
					Msg("[DNS] dns request cancelled")
			} else if errors.Is(err, context2.ManualCanceled) {
				e.
					Str("cause", "context_manual_canceled").
					Str("source", msg.Source).
					Str("qType", D.Type(q.Qtype).String()).
					Str("name", q.Name).
					Msg("[DNS] dns request cancelled")
			} else {
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
	e.Strs("answer", msgToLog(l.ans))
}
