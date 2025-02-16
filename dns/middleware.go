package dns

import (
	"net"
	"net/netip"
	"strings"
	"time"

	D "github.com/miekg/dns"
	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/common/cache"
	"github.com/yaling888/quirktiva/component/fakeip"
	"github.com/yaling888/quirktiva/component/resolver"
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

			host := strings.TrimSuffix(q.Name, ".")

			record := hosts.Search(host)
			if record == nil {
				return next(ctx, r)
			}

			ip := record.Data
			if !isIPRequest(q) {
				if q.Qtype == D.TypeHTTPS {
					var v D.SVCBKeyValue
					if ip.Is4() {
						v = &D.SVCBIPv4Hint{
							Hint: []net.IP{ip.AsSlice()},
						}
					} else if ip.Is6() {
						v = &D.SVCBIPv6Hint{
							Hint: []net.IP{ip.AsSlice()},
						}
					}
					if v != nil {
						rr := &D.HTTPS{
							SVCB: D.SVCB{
								Hdr:      D.RR_Header{Name: q.Name, Rrtype: D.TypeHTTPS, Class: D.ClassINET, Ttl: 3},
								Priority: 1,
								Target:   ".",
								Value:    []D.SVCBKeyValue{v},
							},
						}
						ctx.SetType(context.DNSTypeHost)
						msg := r.Copy()
						msg.Answer = []D.RR{rr}
						msg.SetRcode(r, D.RcodeSuccess)
						msg.Authoritative = true
						msg.RecursionAvailable = true
						return msg, nil
					}
					return handleMsgWithEmptyAnswer(r), nil
				}
				return next(ctx, r)
			}

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
				return handleMsgWithEmptyAnswer(r), nil
			}

			if mapping != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
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
				msg, err := next(ctx, r)
				if err != nil || q.Qtype != D.TypeHTTPS {
					return msg, err
				}
				// should ignore IPv6Hint when disable IPv6 and mapping ip hint for TypeHTTPS
				var rr []D.RR
				for _, answer := range msg.Answer {
					switch ans := answer.(type) {
					case *D.HTTPS:
						var value []D.SVCBKeyValue
						for _, kv := range ans.Value {
							switch val := kv.(type) {
							case *D.SVCBIPv6Hint:
								if resolver.DisableIPv6 {
									continue
								}
								value = append(value, val)
								if _, isCNAME := cnameCache.Get(q.Name); isCNAME {
									continue
								}
								host := strings.TrimSuffix(q.Name, ".")
								ttl := max(ans.Hdr.Ttl, 1)
								for _, ip6 := range val.Hint {
									ip, _ := netip.AddrFromSlice(ip6)
									if !ip.IsGlobalUnicast() {
										continue
									}
									mapping.SetWithExpire(ip, host, time.Now().Add(time.Second*time.Duration(ttl)))
								}
							case *D.SVCBIPv4Hint:
								value = append(value, val)
								if _, isCNAME := cnameCache.Get(q.Name); isCNAME {
									continue
								}
								host := strings.TrimSuffix(q.Name, ".")
								ttl := max(ans.Hdr.Ttl, 1)
								for _, ip4 := range val.Hint {
									ip, _ := netip.AddrFromSlice(ip4.To4())
									if !ip.IsGlobalUnicast() {
										continue
									}
									mapping.SetWithExpire(ip, host, time.Now().Add(time.Second*time.Duration(ttl)))
								}
							default:
								value = append(value, val)
							}
						}
						if value != nil {
							rr = append(rr, &D.HTTPS{
								SVCB: D.SVCB{
									Hdr:      ans.Hdr,
									Priority: ans.Priority,
									Target:   ans.Target,
									Value:    value,
								},
							})
						}
					case *D.CNAME:
						rr = append(rr, ans)
						ttl := max(ans.Hdr.Ttl, 2)
						cnameCache.SetWithExpire(ans.Target, true, time.Now().Add(time.Second*time.Duration(ttl)))
					case *D.AAAA:
						if resolver.DisableIPv6 {
							continue
						}
						rr = append(rr, ans)
					default:
						rr = append(rr, ans)
					}
				}
				m := msg.Copy()
				m.Answer = rr
				return m, nil
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
			case D.TypeAAAA, D.TypeSVCB:
				return handleMsgWithEmptyAnswer(r), nil
			case D.TypeHTTPS:
				msg, err := next(ctx, r)
				if err != nil {
					return nil, err
				}
				// with FakeIP mode should ignore IPv4Hint and IPv6Hint
				ip := fakePool.Lookup(host)
				var rr []D.RR
				for _, answer := range msg.Answer {
					switch ans := answer.(type) {
					case *D.HTTPS:
						var value []D.SVCBKeyValue
						for _, kv := range ans.Value {
							switch val := kv.(type) {
							case *D.SVCBIPv4Hint, *D.SVCBIPv6Hint:
								continue
							default:
								value = append(value, val)
							}
						}
						if ip.Is4() {
							value = append(value, &D.SVCBIPv4Hint{
								Hint: []net.IP{ip.AsSlice()},
							})
						} else if ip.Is6() {
							value = append(value, &D.SVCBIPv6Hint{
								Hint: []net.IP{ip.AsSlice()},
							})
						}
						rr = append(rr, &D.HTTPS{
							SVCB: D.SVCB{
								Hdr:      ans.Hdr,
								Priority: ans.Priority,
								Target:   ans.Target,
								Value:    value,
							},
						})
					case *D.A:
						if !ip.Is4() {
							continue
						}
						rr = append(rr, &D.A{
							Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: dnsDefaultTTL},
							A:   ip.AsSlice(),
						})
					case *D.AAAA:
						if !ip.Is6() || resolver.DisableIPv6 {
							continue
						}
						rr = append(rr, &D.A{
							Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: dnsDefaultTTL},
							A:   ip.AsSlice(),
						})
					}
				}
				if rr == nil {
					var v D.SVCBKeyValue
					if ip.Is4() {
						v = &D.SVCBIPv4Hint{
							Hint: []net.IP{ip.AsSlice()},
						}
					} else if ip.Is6() {
						v = &D.SVCBIPv6Hint{
							Hint: []net.IP{ip.AsSlice()},
						}
					}
					if v != nil {
						rr = append(rr, &D.HTTPS{
							SVCB: D.SVCB{
								Hdr:      D.RR_Header{Name: q.Name, Rrtype: D.TypeHTTPS, Class: D.ClassINET, Ttl: dnsDefaultTTL},
								Priority: 1,
								Target:   ".",
								Value:    []D.SVCBKeyValue{v},
							},
						})
					}
				}
				m := msg.Copy()
				m.Answer = rr
				setMsgTTL(m, 3)
				return m, nil
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
