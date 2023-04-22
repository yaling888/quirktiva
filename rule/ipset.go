package rules

import (
	"github.com/phuslu/log"

	"github.com/Dreamacro/clash/component/ipset"
	C "github.com/Dreamacro/clash/constant"
)

type IPSet struct {
	*Base
	name        string
	adapter     string
	noResolveIP bool
}

func (f *IPSet) RuleType() C.RuleType {
	return C.IPSet
}

func (f *IPSet) Match(metadata *C.Metadata) bool {
	if !metadata.DstIP.IsValid() {
		return false
	}
	exist, err := ipset.Test(f.name, metadata.DstIP)
	if err != nil {
		log.Warn().Err(err).Str("name", f.name).Msg("[Matcher] check ipset failed")
		return false
	}
	return exist
}

func (f *IPSet) Adapter() string {
	return f.adapter
}

func (f *IPSet) Payload() string {
	return f.name
}

func (f *IPSet) ShouldResolveIP() bool {
	return !f.noResolveIP
}

func NewIPSet(name string, adapter string, noResolveIP bool) (*IPSet, error) {
	if err := ipset.Verify(name); err != nil {
		return nil, err
	}

	return &IPSet{
		name:        name,
		adapter:     adapter,
		noResolveIP: noResolveIP,
	}, nil
}

var _ C.Rule = (*IPSet)(nil)
