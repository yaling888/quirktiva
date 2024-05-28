package rules

import (
	"github.com/phuslu/log"

	C "github.com/yaling888/quirktiva/constant"
)

type Group struct {
	*Base
	payload string
	matcher C.Matcher
	rules   []C.Rule
}

func (g *Group) RuleType() C.RuleType {
	return C.Group
}

func (g *Group) Match(metadata *C.Metadata) bool {
	rs, err := g.matcher.Match(metadata)
	if err != nil {
		log.Warn().Err(err).Str("name", g.matcher.Name()).Msg("[Matcher] match group failed")
		return false
	}
	return rs
}

func (g *Group) Adapter() string {
	return ""
}

func (g *Group) Payload() string {
	return g.payload
}

func (g *Group) ShouldResolveIP() bool {
	return false
}

func (g *Group) SubRules() []C.Rule {
	return g.rules
}

func (g *Group) RuleExtra() *C.RuleExtra {
	return nil
}

func NewGroup(payload string, matcher C.Matcher, rules []C.Rule) *Group {
	return &Group{
		Base:    &Base{},
		payload: payload,
		matcher: matcher,
		rules:   rules,
	}
}

var _ C.Rule = (*Group)(nil)
