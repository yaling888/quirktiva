package mitm

import (
	"reflect"
	"strings"
)

type Env struct {
	Data map[string]any `expr:"data"`
}

func (e Env) Assign(key string, value any) bool {
	after, _ := strings.CutPrefix(key, "data.")
	keys := strings.Split(after, ".")
	data := e.Data
	for i, l := 0, len(keys); i < l; i++ {
		k := keys[i]
		if i == l-1 {
			if v, ok := data[k]; ok && reflect.ValueOf(v).Kind() != reflect.ValueOf(value).Kind() {
				return false
			}
			data[k] = value
			return true
		}
		if sub, ok := data[k].(map[string]any); ok {
			data = sub
		} else {
			return false
		}
	}
	return false
}

func (e Env) delete(key string) bool {
	after, _ := strings.CutPrefix(key, "data.")
	keys := strings.Split(after, ".")
	data := e.Data
	for i, l := 0, len(keys); i < l; i++ {
		k := keys[i]
		if i == l-1 {
			if _, ok := data[k]; ok {
				delete(data, k)
				return true
			}
			return false
		}
		if sub, ok := data[k].(map[string]any); ok {
			data = sub
		} else {
			return false
		}
	}
	return false
}

func (e Env) Delete(keys string) bool {
	var v bool
	for _, k := range strings.Split(keys, ";") {
		v1 := e.delete(k)
		v = v || v1
	}
	return v
}

func (e Env) DeleteArray(key string, key1 string, value any) bool {
	after, _ := strings.CutPrefix(key, "data.")
	keys := strings.Split(after, ".")
	data := e.Data
	var vss []string
	if s, ok := value.(string); ok {
		vss = strings.Split(s, ";;")
	}
	for i, l := 0, len(keys); i < l; i++ {
		if i == l-1 {
			switch arr := data[keys[i]].(type) {
			case []any:
				tmp := make([]any, 0, len(arr))
				for _, v := range arr {
					if m, ok := v.(map[string]any); ok {
						if len(vss) != 0 {
							a := true
							for _, s := range vss {
								a = a && m[key1] != s
							}
							if a {
								tmp = append(tmp, m)
							}
						} else if m[key1] != value {
							tmp = append(tmp, m)
						}
					}
				}
				if len(tmp) != 0 {
					data[keys[i]] = tmp
					return true
				}
				return false
			}
			return false
		}
		if sub, ok := data[keys[i]].(map[string]any); ok {
			data = sub
		} else {
			return false
		}
	}
	return false
}
