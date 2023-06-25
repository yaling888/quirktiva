package rewrites

import (
	"testing"

	regexp "github.com/dlclark/regexp2"
	"github.com/stretchr/testify/assert"

	"github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"
)

func TestRewrite(t *testing.T) {
	line0 := `^https?://example\.com/resource1/3/ url reject-dict`
	line1 := `^https?://example\.com/(resource2)/ url 307 https://example.com/new-$1/`
	line2 := `^https?://example\.com/resource4/ url request-header (\r\n)User-Agent:.+(\r\n) request-header $1User-Agent: Clash/1.0$2`
	line3 := `should be error`

	c0, err0 := ParseRewrite(line0)
	c1, err1 := ParseRewrite(line1)
	c2, err2 := ParseRewrite(line2)
	_, err3 := ParseRewrite(line3)

	assert.NotNil(t, err3)

	assert.Nil(t, err0)
	assert.Equal(t, c0.RuleType(), constant.MitmRejectDict)

	assert.Nil(t, err1)
	assert.Equal(t, c1.RuleType(), constant.Mitm307)
	assert.Equal(t, c1.URLRegx(), regexp.MustCompile(`^https?://example\.com/(resource2)/`, 0))
	assert.Equal(t, c1.RulePayload(), "https://example.com/new-$1/")

	assert.Nil(t, err2)
	assert.Equal(t, c2.RuleType(), constant.MitmRequestHeader)
	assert.Equal(t, c2.RuleRegx(), regexp.MustCompile(`(\r\n)User-Agent:.+(\r\n)`, 0))
	assert.Equal(t, c2.RulePayload(), "$1User-Agent: Clash/1.0$2")

	req := []constant.Rewrite{c0, c1}
	res := []constant.Rewrite{c2}
	tunnel.UpdateRewrites(nil, NewRewriteRules(req, res))

	rule, sub, found := matchRewriteRule("https://example.com/resource2/", true)
	assert.True(t, found)
	assert.Equal(t, sub, []string{"https://example.com/resource2/", "resource2"})

	ss := rule.ReplaceURLPayload(sub)
	assert.Equal(t, ss, "https://example.com/new-resource2/")

	rule1, _, found := matchRewriteRule("https://example.com/resource4/", false)
	found = found && rule1.RuleRegx() != nil
	assert.True(t, found)

	ss1 := rule1.ReplaceSubPayload("Ae: test1\r\nUser-Agent: Test/0.1\r\nVc: test2")
	assert.Equal(t, ss1, "Ae: test1\r\nUser-Agent: Clash/1.0\r\nVc: test2")
}
