package constant

const ScriptRuleGeoSiteTarget = "__WhateverTarget__"

var (
	scriptRuleProviders     = map[string]Rule{}
	GetScriptProxyProviders = defaultProxyProvidersGetter

	scriptRuleProvidersBackup        map[string]Rule
	scriptProxyProvidersGetterBackup func() map[string][]Proxy
)

type Matcher interface {
	Eval(metadata *Metadata) (string, error)
	Match(metadata *Metadata) (bool, error)
}

func defaultProxyProvidersGetter() map[string][]Proxy {
	return nil
}

func SetScriptRuleProviders(rp map[string]Rule) {
	scriptRuleProviders = rp
}

func GetScriptRuleProviders() map[string]Rule {
	return scriptRuleProviders
}

func BackupScriptState() {
	scriptRuleProvidersBackup = scriptRuleProviders
	scriptProxyProvidersGetterBackup = GetScriptProxyProviders
}

func RestoreScriptState() {
	scriptRuleProviders = scriptRuleProvidersBackup
	GetScriptProxyProviders = scriptProxyProvidersGetterBackup

	scriptRuleProvidersBackup = nil
	scriptProxyProvidersGetterBackup = nil
}
