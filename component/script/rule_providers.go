package script

import (
	"fmt"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	C "github.com/Dreamacro/clash/constant"
)

var (
	_ starlark.Mapping = (*RuleProviders)(nil)

	ruleProviderModules = make(map[string]*starlarkstruct.Module)
)

type RuleProviders struct {
	starlark.Value
}

func (r *RuleProviders) Type() string {
	return "rule_providers"
}

func (r *RuleProviders) Get(value starlark.Value) (v starlark.Value, found bool, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("call rule_providers error: %w", err)
		}
	}()

	var name starlark.String
	if name, found = value.(starlark.String); !found {
		err = fmt.Errorf("invalid key type")
		return
	}

	providerName := name.GoString()
	providerName = strings.TrimPrefix(providerName, "geosite:")

	if _, found = C.GetScriptRuleProviders()[providerName]; !found {
		err = fmt.Errorf("provider [%s] not found", providerName)
		return
	}

	module := ruleProviderModules[providerName]
	if module == nil {
		module = &starlarkstruct.Module{
			Name: "match_" + providerName,
			Members: starlark.StringDict{
				"match": starlark.NewBuiltin(providerName, matchRuleProvider),
			},
		}
		ruleProviderModules[providerName] = module
	}

	v = module
	return
}

func newRuleProviders() starlark.Value {
	return &RuleProviders{}
}
