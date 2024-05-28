package script

import (
	"errors"
	"fmt"
	T "time"

	"go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"

	C "github.com/yaling888/quirktiva/constant"
)

const metadataLocalKey = "local.metadata_key"

var allowKeywords = map[string]bool{
	"_metadata":     true,
	"now":           true,
	"type":          true,
	"network":       true,
	"host":          true,
	"process_name":  true,
	"process_path":  true,
	"src_ip":        true,
	"src_port":      true,
	"dst_ip":        true,
	"dst_port":      true,
	"user_agent":    true,
	"special_proxy": true,
	"inbound_port":  true,
}

var parseOption = syntax.LegacyFileOptions()

var nowErrFunc = func() (T.Time, error) {
	return T.Now(), nil
}

var _ C.Matcher = (*Matcher)(nil)

type Matcher struct {
	name string
	key  string

	program *starlark.Program
}

func (m *Matcher) Name() string {
	return m.name
}

func (m *Matcher) Eval(metadata *C.Metadata) (string, error) {
	metadataDict, err := metadataToDict(metadata)
	if err != nil {
		return "", err
	}

	predefined := make(starlark.StringDict)
	predefined["_metadata"] = metadataDict

	thread := &starlark.Thread{
		Print: func(_ *starlark.Thread, _ string) {},
	}

	thread.SetLocal(metadataLocalKey, metadata)

	time.SetNow(thread, nowErrFunc)

	results, err := m.program.Init(thread, predefined)
	if err != nil {
		return "", err
	}

	evalResult := results[m.key]
	if v, ok := evalResult.(starlark.String); ok {
		return v.GoString(), nil
	}

	if evalResult == nil {
		return "", errors.New("invalid return type, got <nil>, want string")
	}

	return "", fmt.Errorf("invalid return type, got %s, want string", evalResult.Type())
}

func (m *Matcher) Match(metadata *C.Metadata) (bool, error) {
	predefined, err := metadataToStringDict(metadata, nil)
	if err != nil {
		return false, err
	}

	predefined["now"] = time.Time(T.Now())

	thread := &starlark.Thread{
		Print: func(_ *starlark.Thread, _ string) {},
	}

	thread.SetLocal(metadataLocalKey, metadata)

	time.SetNow(thread, nowErrFunc)

	results, err := m.program.Init(thread, predefined)
	if err != nil {
		return false, err
	}

	evalResult := results[m.key]
	if v, ok := evalResult.(starlark.Bool); ok {
		return bool(v), nil
	}

	if evalResult == nil {
		return false, errors.New("invalid return type, got <nil>, want bool")
	}

	return false, fmt.Errorf("invalid return type, got %s, want bool", evalResult.Type())
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

	starFile, err := parseOption.Parse(filename, code, 0)
	if err != nil {
		return nil, fmt.Errorf("parse script code error: %w", err)
	}

	program, err := starlark.FileProgram(starFile, func(s string) bool {
		rs, ok := allowKeywords[s]
		return ok && rs
	})
	if err != nil {
		return nil, fmt.Errorf("compile script code error: %w", err)
	}

	return &Matcher{
		name:    name,
		key:     key,
		program: program,
	}, nil
}
