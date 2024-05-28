package script

import (
	"fmt"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/expr-lang/expr/vm/runtime"

	C "github.com/yaling888/quirktiva/constant"
)

var inStringPatch = &stringInString{}

var _ C.Matcher = (*ExprMatcher)(nil)

type ExprMatcher struct {
	name    string
	hasNow  bool
	program *vm.Program
}

func (e *ExprMatcher) Name() string {
	return e.name
}

func (*ExprMatcher) Eval(*C.Metadata) (string, error) {
	panic("unimplemented")
}

func (e *ExprMatcher) Match(mtd *C.Metadata) (bool, error) {
	env := parseEnv(mtd, e.hasNow)

	result, err := expr.Run(e.program, env)
	if err != nil {
		return false, err
	}

	if v, ok := result.(bool); ok {
		return v, nil
	}

	return false, fmt.Errorf("invalid return type, got %T, want bool", result)
}

func NewExprMatcher(name, code string) (*ExprMatcher, error) {
	options := []expr.Option{
		expr.Env(shortcutEnvironment{}),
		expr.Patch(inStringPatch),
		expr.AsBool(),
	}

	program, err := expr.Compile(code, options...)
	if err != nil {
		return nil, fmt.Errorf("compile expr code error: %w", err)
	}

	var hasNow bool
	for _, m := range program.Constants {
		if f, ok := m.(*runtime.Field); ok {
			if l := len(f.Path); l != 0 && f.Path[0] == "now" {
				hasNow = true
				break
			}
		}
	}

	return &ExprMatcher{
		name:    name,
		hasNow:  hasNow,
		program: program,
	}, nil
}
