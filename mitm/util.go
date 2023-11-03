package mitm

import (
	"strings"

	regexp "github.com/dlclark/regexp2"
)

var allowContentType = []string{
	"text/",
	"application/xhtml",
	"application/xml",
	"application/atom+xml",
	"application/json",
	"application/x-www-form-urlencoded",
}

func CanRewriteBody(contentLength int64, contentEncoding, contentType string) bool {
	if contentLength <= 0 && contentEncoding == "" {
		return false
	}

	for _, v := range allowContentType {
		if strings.HasPrefix(contentType, v) {
			return true
		}
	}

	return false
}

func findStringSubmatch(re *regexp.Regexp, s string) []string {
	var sub []string
	m, _ := re.FindStringMatch(s)
	for m != nil {
		for _, g := range m.Groups() {
			for _, c := range g.Captures {
				sub = append(sub, c.String())
			}
		}
		m, _ = re.FindNextMatch(m)
	}
	return sub
}
