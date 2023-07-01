package script

import (
	"testing"

	"github.com/stretchr/testify/assert"

	C "github.com/Dreamacro/clash/constant"
)

func TestStringInString(t *testing.T) {
	code := `("example" in host) and ("com" in host)`
	m, err := NewExprMatcher("test", code)
	assert.NoError(t, err)

	mtd := &C.Metadata{
		Host: "example.com",
	}

	v, err := m.Match(mtd)
	assert.NoError(t, err)
	assert.True(t, v)

	mtd.Host = "test1.com"
	v, err = m.Match(mtd)
	assert.NoError(t, err)
	assert.False(t, v)

	code2 := `"test-" in "a-test-b"`
	m2, err := NewExprMatcher("test2", code2)
	assert.NoError(t, err)

	v, err = m2.Match(mtd)
	assert.NoError(t, err)
	assert.True(t, v)

	code3 := `22 in [33, 44]`
	m3, err := NewExprMatcher("test3", code3)
	assert.NoError(t, err)

	v, err = m3.Match(mtd)
	assert.NoError(t, err)
	assert.False(t, v)
}
