package script

import (
	"fmt"
	"reflect"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"

	C "github.com/Dreamacro/clash/constant"
)

var _ C.Matcher = (*ExprMatcher)(nil)

type ExprMatcher struct {
	name    string
	program *vm.Program
}

func (e *ExprMatcher) Name() string {
	return e.name
}

func (e *ExprMatcher) Eval(_ *C.Metadata) (string, error) {
	panic("unimplemented")
}

func (e *ExprMatcher) Match(mtd *C.Metadata) (bool, error) {
	env := parseEnv(mtd)

	result, err := expr.Run(e.program, env)
	if err != nil {
		return false, err
	}

	if v, ok := result.(bool); ok {
		return v, nil
	}

	return false, fmt.Errorf("invalid return type, got %v, want bool", reflect.TypeOf(result))
}

func NewExprMatcher(name, code string) (*ExprMatcher, error) {
	options := []expr.Option{
		expr.Env(shortcutEnvironment{}),
		expr.Patch(&stringInString{}),
		expr.AsBool(),
	}

	program, err := expr.Compile(code, options...)
	if err != nil {
		return nil, fmt.Errorf("compile script code error: %w", err)
	}

	return &ExprMatcher{
		name:    name,
		program: program,
	}, nil
}
