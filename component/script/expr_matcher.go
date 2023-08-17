package script

import (
	"fmt"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"

	C "github.com/Dreamacro/clash/constant"
)

var (
	_ C.Matcher = (*ExprMatcher)(nil)

	inStringPatch = &stringInString{}
)

type ExprMatcher struct {
	name    string
	program *vm.Program
}

func (e *ExprMatcher) Name() string {
	return e.name
}

func (*ExprMatcher) Eval(*C.Metadata) (string, error) {
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

	return false, fmt.Errorf("invalid return type, got %T, want bool", result)
}

func NewExprMatcher(name, code string) (*ExprMatcher, error) {
	options := []expr.Option{
		expr.Env(shortcutEnvironment{}),
		expr.Patch(inStringPatch),
		expr.AsBool(),
	}

	if strings.Contains(code, " | ") {
		options = append(options, expr.ExperimentalPipes())
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
