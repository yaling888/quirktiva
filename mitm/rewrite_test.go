package mitm

import (
	"testing"

	regexp "github.com/dlclark/regexp2"
	"github.com/stretchr/testify/assert"

	"github.com/yaling888/quirktiva/constant"
	"github.com/yaling888/quirktiva/tunnel"
)

func TestRewrite(t *testing.T) {
	line0 := `^https?://example\.com/resource1/3/ url reject-dict`
	line1 := `^https?://example\.com/(resource2)/ url 307 https://example.com/new-$1/`
	line2 := `^https?://example\.com/resource4/ url request-header (\r\n)User-Agent:.+(\r\n) request-header $1User-Agent: Clash/1.0$2`
	line3 := `should be error`
	line4 := `^https?://example\.com/resource4/5/ url reject-200 {"responseContext": {}}`
	line5 := `^https?://example\.com/resource5/ url response-body "serviceTrackingParams":.+("maxAgeSeconds":)` +
		payloadSeparator + `"mainAppWebResponseContext":.+("webResponseContextExtensionData":)` +
		` response-body $1` + payloadSeparator + `$1`

	body := `"serviceTrackingParams": [{}],"maxAgeSeconds": 0,"mainAppWebResponseContext": {},"webResponseContextExtensionData": {}`
	newBody := `"maxAgeSeconds": 0,"webResponseContextExtensionData": {}`

	c0, err0 := ParseRewrite(line0)
	c1, err1 := ParseRewrite(line1)
	c2, err2 := ParseRewrite(line2)
	_, err3 := ParseRewrite(line3)
	c4, err4 := ParseRewrite(line4)
	c5, err5 := ParseRewrite(line5)

	assert.NotNil(t, err3)

	assert.Nil(t, err0)
	assert.Equal(t, c0.RuleType(), constant.MitmRejectDict)
	assert.Nil(t, c0.RulePayload())

	assert.Nil(t, err1)
	assert.Equal(t, c1.RuleType(), constant.Mitm307)
	assert.Equal(t, c1.URLRegx(), regexp.MustCompile(`^https?://example\.com/(resource2)/`, 0))
	assert.Equal(t, c1.RulePayload()[0], "https://example.com/new-$1/")

	assert.Nil(t, err2)
	assert.Equal(t, c2.RuleType(), constant.MitmRequestHeader)
	assert.Equal(t, c2.RuleRegx()[0], regexp.MustCompile(`(\r\n)User-Agent:.+(\r\n)`, 0))
	assert.Equal(t, c2.RulePayload()[0], "$1User-Agent: Clash/1.0$2")

	assert.Nil(t, err4)
	assert.Equal(t, c4.RuleType(), constant.MitmReject200)
	assert.Equal(t, c4.RulePayload()[0], "{\"responseContext\": {}}")

	assert.Nil(t, err5)
	assert.Equal(t, c5.RuleType(), constant.MitmResponseBody)

	req := []constant.Rewrite{c0, c1, c2}
	res := []constant.Rewrite{c5}
	tunnel.UpdateRewrites(nil, NewRewriteRules(req, res))

	rule, sub, found := matchRewriteRule("https://example.com/resource2/321/234?dsa=14321", true)
	assert.True(t, found)
	assert.Equal(t, sub, []string{"https://example.com/resource2/", "resource2"})

	ss := rule.ReplaceURLPayload(sub)
	assert.Equal(t, ss, "https://example.com/new-resource2/")

	rule1, _, found := matchRewriteRule("https://example.com/resource4/", true)
	found = found && rule1.RuleRegx() != nil
	assert.True(t, found)

	ss1, ok := rule1.ReplaceSubPayload("Ae: test1\r\nUser-Agent: Test/0.1\r\nVc: test2")
	assert.True(t, ok)
	assert.Equal(t, ss1, "Ae: test1\r\nUser-Agent: Clash/1.0\r\nVc: test2")

	rule2, _, found := matchRewriteRule("https://example.com/resource5/", false)
	found = found && rule2.RuleRegx() != nil
	assert.True(t, found)
	assert.Equal(t, rule2.RuleType(), constant.MitmResponseBody)

	ss2, ok := rule2.ReplaceSubPayload(body)
	assert.True(t, ok)
	assert.Equal(t, ss2, newBody)
}
