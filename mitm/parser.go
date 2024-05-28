package mitm

import (
	"strings"

	regexp "github.com/dlclark/regexp2"

	C "github.com/yaling888/quirktiva/constant"
)

const payloadSeparator = "<and>"

func ParseRewrite(line string) (C.Rewrite, error) {
	url, others, found := strings.Cut(strings.TrimSpace(line), "url")
	if !found {
		return nil, errInvalid
	}

	var (
		ruleType    *C.RewriteType
		ruleRegx    []*regexp.Regexp
		rulePayload []string
	)

	urlRegx, err := regexp.Compile(strings.Trim(url, " "), 0)
	if err != nil {
		return nil, err
	}

	others = strings.Trim(others, " ")
	first := strings.Split(others, " ")[0]
	for k, v := range C.RewriteTypeMapping {
		if k == others {
			ruleType = &v
			break
		}

		if k != first {
			continue
		}

		rs := trimArr(strings.Split(others, k))
		l := len(rs)
		if l > 2 {
			continue
		}

		if l == 1 {
			ruleType = &v
			rulePayload = trimArr(strings.Split(rs[0], payloadSeparator))
			break
		} else {
			for _, str := range trimArr(strings.Split(rs[0], payloadSeparator)) {
				regx, err := regexp.Compile(str, 0)
				if err != nil {
					return nil, err
				}
				ruleRegx = append(ruleRegx, regx)
			}

			ruleType = &v
			rulePayload = trimArr(strings.Split(rs[1], payloadSeparator))
			break
		}
	}

	if ruleType == nil {
		return nil, errInvalid
	}

	return NewRewriteRule(urlRegx, *ruleType, ruleRegx, rulePayload), nil
}

func trimArr(arr []string) (r []string) {
	for _, e := range arr {
		if s := strings.Trim(e, " "); s != "" {
			r = append(r, s)
		}
	}
	return
}
