package dns

import (
	"errors"
	"net"

	D "github.com/miekg/dns"
	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/common/sockopt"
	"github.com/yaling888/quirktiva/context"
)

var (
	address string
	server  = &Server{}

	dnsDefaultTTL uint32 = 600
)

type Server struct {
	*D.Server
	handler handler
}

// ServeDNS implement D.Handler ServeDNS
func (s *Server) ServeDNS(w D.ResponseWriter, r *D.Msg) {
	msg, err := handlerWithContext(s.handler, r)
	if err != nil {
		D.HandleFailed(w, r)
		return
	}
	msg.Compress = true
	_ = w.WriteMsg(msg)
}

func handlerWithContext(handler handler, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("at least one question is required")
	}

	ctx := context.NewDNSContext(msg)
	return handler(ctx, msg)
}

func (s *Server) SetHandler(handler handler) {
	s.handler = handler
}

func ReCreateServer(addr string, resolver *Resolver, mapper *ResolverEnhancer) {
	if addr == address && resolver != nil {
		mHandler := newHandler(resolver, mapper)
		server.SetHandler(mHandler)
		return
	}

	if server.Server != nil {
		_ = server.Shutdown()
		server = &Server{}
		address = ""
	}

	if addr == "" {
		return
	}

	var err error
	defer func() {
		if err != nil {
			log.Error().Err(err).Msg("[DNS] server start failed")
		}
	}()

	_, port, err := net.SplitHostPort(addr)
	if port == "0" || port == "" || err != nil {
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}

	p, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return
	}

	err = sockopt.UDPReuseaddr(p)
	if err != nil {
		log.Warn().Err(err).Msg("[DNS] reuse UDP address failed")

		err = nil
	}

	address = addr
	mHandler := newHandler(resolver, mapper)
	server = &Server{handler: mHandler}
	server.Server = &D.Server{Addr: addr, PacketConn: p, Handler: server}

	go func() {
		_ = server.ActivateAndServe()
	}()

	log.Info().Str("addr", p.LocalAddr().String()).Msg("[DNS] server listening")
}
