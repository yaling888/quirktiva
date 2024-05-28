package constant

import (
	"fmt"

	"github.com/yaling888/quirktiva/component/geodata/router"
)

// Rule Type
const (
	Domain RuleType = iota
	DomainSuffix
	DomainKeyword
	GEOSITE
	GEOIP
	IPCIDR
	SrcIPCIDR
	SrcPort
	DstPort
	InboundPort
	Process
	ProcessPath
	Script
	UserAgent
	IPSet
	MATCH
	Group
)

type RuleType int

func (rt RuleType) String() string {
	switch rt {
	case Domain:
		return "Domain"
	case DomainSuffix:
		return "DomainSuffix"
	case DomainKeyword:
		return "DomainKeyword"
	case GEOSITE:
		return "GeoSite"
	case GEOIP:
		return "GeoIP"
	case IPCIDR:
		return "IPCIDR"
	case SrcIPCIDR:
		return "SrcIPCIDR"
	case SrcPort:
		return "SrcPort"
	case DstPort:
		return "DstPort"
	case InboundPort:
		return "InboundPort"
	case Process:
		return "Process"
	case ProcessPath:
		return "ProcessPath"
	case Script:
		return "Script"
	case UserAgent:
		return "UserAgent"
	case IPSet:
		return "IPSet"
	case MATCH:
		return "Match"
	case Group:
		return "Group"
	default:
		return "Unknown"
	}
}

type RuleGroup []string

func (rg RuleGroup) String() string {
	l := len(rg)
	switch l {
	case 0:
		return ""
	case 1:
		return rg[0]
	default:
		return fmt.Sprintf("%s[%s]", rg[l-1], rg[0])
	}
}

type LogRule struct {
	R Rule
}

func (l LogRule) String() string {
	return fmt.Sprintf("%s(%s)", l.R.RuleType().String(), l.R.Payload())
}

type Rule interface {
	RuleType() RuleType
	Match(metadata *Metadata) bool
	Adapter() string
	Payload() string
	ShouldResolveIP() bool
	RuleExtra() *RuleExtra
	SetRuleExtra(re *RuleExtra)
	ShouldFindProcess() bool
	SubRules() []Rule
	RuleGroups() RuleGroup
	AppendGroup(group string)
}

type RuleGeoSite interface {
	GetDomainMatcher() *router.DomainMatcher
}
