package context

import (
	"github.com/miekg/dns"

	"github.com/yaling888/quirktiva/common/uuid"
)

const (
	DNSTypeHost   = "host"
	DNSTypeFakeIP = "fakeip"
	DNSTypeRaw    = "raw"
)

type DNSContext struct {
	id  uuid.UUID
	msg *dns.Msg
	tp  string
}

func NewDNSContext(msg *dns.Msg) *DNSContext {
	id := uuid.RandomB64Hlf()
	return &DNSContext{
		id:  id,
		msg: msg,
	}
}

// ID implement C.PlainContext ID
func (c *DNSContext) ID() uuid.UUID {
	return c.id
}

// SetType set type of response
func (c *DNSContext) SetType(tp string) {
	c.tp = tp
}

// Type return type of response
func (c *DNSContext) Type() string {
	return c.tp
}
