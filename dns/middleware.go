package dns

import (
	"net/netip"
	"strings"
	"time"

	D "github.com/miekg/dns"
	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/common/cache"
	"github.com/yaling888/quirktiva/component/fakeip"
	"github.com/yaling888/quirktiva/component/trie"
	C "github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/context"
)

type (
	handler    func(ctx *context.DNSContext, r *D.Msg) (*D.Msg, error)
	middleware func(next handler) handler
)

func withHosts(hosts *trie.DomainTrie[netip.Addr], mapping *cache.LruCache[netip.Addr, string]) middleware {
	return func(next handler) handler {
		return func(ctx *context.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			if !isIPRequest(q) {
				return next(ctx, r)
			}

			host := strings.TrimSuffix(q.Name, ".")

			record := hosts.Search(host)
			if record == nil {
				return next(ctx, r)
			}

			ip := record.Data
			msg := r.Copy()

			if ip.Is4() && q.Qtype == D.TypeA {
				rr := &D.A{}
				rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 3}
				rr.A = ip.AsSlice()

				msg.Answer = []D.RR{rr}
			} else if ip.Is6() && q.Qtype == D.TypeAAAA {
				rr := &D.AAAA{}
				rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 3}
				rr.AAAA = ip.AsSlice()

				msg.Answer = []D.RR{rr}
			} else {
				return next(ctx, r)
			}

			if mapping != nil {
				mapping.SetWithExpire(ip, host, time.Now().Add(time.Second*3))
			}

			ctx.SetType(context.DNSTypeHost)
			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true

			return msg, nil
		}
	}
}

func withMapping(mapping *cache.LruCache[netip.Addr, string], cnameCache *cache.LruCache[string, bool]) middleware {
	return func(next handler) handler {
		return func(ctx *context.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			if !isIPRequest(q) {
				return next(ctx, r)
			}

			msg, err := next(ctx, r)
			if err != nil {
				return nil, err
			}

			host := strings.TrimSuffix(q.Name, ".")
			_, isCNAME := cnameCache.Get(q.Name)
			for _, ans := range msg.Answer {
				var (
					ip  netip.Addr
					ttl uint32
				)

				switch a := ans.(type) {
				case *D.A:
					if isCNAME {
						continue
					}
					ip, _ = netip.AddrFromSlice(a.A.To4())
					if !ip.IsGlobalUnicast() {
						continue
					}
					ttl = a.Hdr.Ttl
				case *D.AAAA:
					if isCNAME {
						continue
					}
					ip, _ = netip.AddrFromSlice(a.AAAA)
					if !ip.IsGlobalUnicast() {
						continue
					}
					ttl = a.Hdr.Ttl
				case *D.CNAME:
					ttl = max(a.Hdr.Ttl, 2)
					cnameCache.SetWithExpire(a.Target, true, time.Now().Add(time.Second*time.Duration(ttl)))
					continue
				default:
					continue
				}

				ttl = max(ttl, 1)
				mapping.SetWithExpire(ip, host, time.Now().Add(time.Second*time.Duration(ttl)))
			}

			return msg, nil
		}
	}
}

func withFakeIP(fakePool *fakeip.Pool) middleware {
	return func(next handler) handler {
		return func(ctx *context.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			host := strings.TrimSuffix(q.Name, ".")
			if fakePool.ShouldSkipped(host) {
				return next(ctx, r)
			}

			switch q.Qtype {
			case D.TypeAAAA, D.TypeSVCB, D.TypeHTTPS:
				return handleMsgWithEmptyAnswer(r), nil
			}

			if q.Qtype != D.TypeA {
				return next(ctx, r)
			}

			rr := &D.A{}
			rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: dnsDefaultTTL}
			ip := fakePool.Lookup(host)
			rr.A = ip.AsSlice()
			msg := r.Copy()
			msg.Answer = []D.RR{rr}

			ctx.SetType(context.DNSTypeFakeIP)
			setMsgTTL(msg, 3)
			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true

			return msg, nil
		}
	}
}

func withResolver(resolver *Resolver) handler {
	return func(ctx *context.DNSContext, r *D.Msg) (*D.Msg, error) {
		ctx.SetType(context.DNSTypeRaw)
		q := r.Question[0]

		// return an empty AAAA msg when ipv6 disabled
		if !resolver.ipv6 && q.Qtype == D.TypeAAAA {
			return handleMsgWithEmptyAnswer(r), nil
		}

		msg, _, err := resolver.Exchange(r)
		if err != nil {
			log.Debug().Err(err).
				Str("name", q.Name).
				Str("qClass", D.Class(q.Qclass).String()).
				Str("qType", D.Type(q.Qtype).String()).
				Msg("[DNS] exchange failed")
			return nil, err
		}
		msg.SetRcode(r, msg.Rcode)
		msg.Authoritative = true

		return msg, nil
	}
}

func compose(middlewares []middleware, endpoint handler) handler {
	length := len(middlewares)
	h := endpoint
	for i := length - 1; i >= 0; i-- {
		mMiddleware := middlewares[i]
		h = mMiddleware(h)
	}

	return h
}

func newHandler(resolver *Resolver, mapper *ResolverEnhancer) handler {
	middlewares := []middleware{}

	if resolver.hosts != nil {
		middlewares = append(middlewares, withHosts(resolver.hosts, mapper.mapping))
	}

	if mapper.mode == C.DNSFakeIP {
		middlewares = append(middlewares, withFakeIP(mapper.fakePool))
	}

	if mapper.mode != C.DNSNormal {
		middlewares = append(middlewares, withMapping(mapper.mapping, mapper.cnameCache))
	}

	return compose(middlewares, withResolver(resolver))
}
