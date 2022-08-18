package script

import (
	"fmt"

	"github.com/gofrs/uuid"
	"go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"

	C "github.com/Dreamacro/clash/constant"
)

const metadataLocalKey = "local.metadata_key"

var keywordAllow = map[string]bool{
	"_metadata":    true,
	"now":          true,
	"type":         true,
	"network":      true,
	"host":         true,
	"process_name": true,
	"process_path": true,
	"src_ip":       true,
	"src_port":     true,
	"dst_ip":       true,
	"dst_port":     true,
	"user_agent":   true,
}

var _ C.Matcher = (*Matcher)(nil)

type Matcher struct {
	name string
	key  string

	program *starlark.Program
}

func NewMatcher(name, filename, code string) (_ *Matcher, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parse script code panic: %v", r)
		}
	}()

	if filename == "" {
		filename = name + ".star"
	}

	key := fmt.Sprintf("_%s_eval", name)
	if name == "main" {
		code = fmt.Sprintf("%s\n\n%s=main(_clash_ctx, _metadata)\n", code, key)
	} else {
		code = fmt.Sprintf("%s=(%s)", key, code)
	}

	starFile, err := syntax.Parse(filename, code, 0)
	if err != nil {
		return nil, fmt.Errorf("parse script code error: %w", err)
	}

	p, err := starlark.FileProgram(starFile, func(s string) bool {
		return keywordAllow[s] == true
	})
	if err != nil {
		return nil, fmt.Errorf("program script code error: %w", err)
	}

	return &Matcher{
		name:    name,
		key:     key,
		program: p,
	}, nil
}

func (m *Matcher) Eval(metadata *C.Metadata) (string, error) {
	metadataDict, err := metadataToDict(metadata)
	if err != nil {
		return "", fmt.Errorf("eval script function [%s] error: %w", m.name, err)
	}

	predefined := make(starlark.StringDict)
	predefined["_metadata"] = metadataDict

	id, _ := uuid.NewV4()
	thread := &starlark.Thread{
		Name:  m.name + "-" + id.String(),
		Print: func(_ *starlark.Thread, _ string) {},
	}

	thread.SetLocal(metadataLocalKey, metadata)

	results, err := m.program.Init(thread, predefined)
	if err != nil {
		return "", fmt.Errorf("eval script function [%s] error: %w", m.name, err)
	}

	evalResult := results[m.key]
	if evalResult == nil {
		return "", fmt.Errorf("eval script function [%s] error: return value is nil", m.name)
	}

	if v, ok := evalResult.(starlark.String); ok {
		return v.GoString(), nil
	}

	return "", fmt.Errorf("eval script function [%s] error: invalid return type, got %s, want string", m.name, evalResult.Type())
}

func (m *Matcher) Match(metadata *C.Metadata) (bool, error) {
	predefined, err := metadataToStringDict(metadata, nil)
	if err != nil {
		return false, fmt.Errorf("match shortcut [%s] error: %w", m.name, err)
	}

	predefined["now"] = time.Time(time.NowFunc())

	id, _ := uuid.NewV4()
	thread := &starlark.Thread{
		Name:  m.name + "-" + id.String(),
		Print: func(_ *starlark.Thread, _ string) {},
	}

	thread.SetLocal(metadataLocalKey, metadata)

	results, err := m.program.Init(thread, predefined)
	if err != nil {
		return false, fmt.Errorf("match shortcut [%s] error: %w", m.name, err)
	}

	evalResult := results[m.key]
	if evalResult == nil {
		return false, fmt.Errorf("match shortcut [%s] error: return value is nil", m.name)
	}

	if v, ok := evalResult.(starlark.Bool); ok {
		return bool(v), nil
	}

	return false, fmt.Errorf("match shortcut [%s] error: invalid return type, got %s, want bool", m.name, evalResult.Type())
}
