package script

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	C "github.com/yaling888/quirktiva/constant"
)

func TestSLNow(t *testing.T) {
	now := time.Now()
	hour := now.Hour()
	minute := now.Minute()
	second := now.Second()
	code := fmt.Sprintf(`now.hour == %d and now.minute == %d and now.second == %d`, hour, minute, second)
	m, err := NewMatcher("test", "test", code)
	assert.NoError(t, err)

	v, err := m.Match(&C.Metadata{})
	assert.NoError(t, err)
	assert.True(t, v)
}
