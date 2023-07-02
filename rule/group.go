package rules

import (
	"github.com/phuslu/log"

	C "github.com/Dreamacro/clash/constant"
)

type Group struct {
	*Base
	name    string
	matcher C.Matcher
	rules   []C.Rule
}

func (g *Group) RuleType() C.RuleType {
	return C.Group
}

func (g *Group) Match(metadata *C.Metadata) bool {
	rs, err := g.matcher.Match(metadata)
	if err != nil {
		log.Warn().Err(err).Str("name", g.name).Msg("[Matcher] match group failed")
		return false
	}
	return rs
}

func (g *Group) Adapter() string {
	return ""
}

func (g *Group) Payload() string {
	return g.name
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

func NewGroup(name string, matcher C.Matcher, rules []C.Rule) *Group {
	return &Group{
		Base:    &Base{},
		name:    name,
		matcher: matcher,
		rules:   rules,
	}
}

var _ C.Rule = (*Group)(nil)
