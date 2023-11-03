package provider

import (
	"net/textproto"
	"strconv"
	"strings"
)

type Subscription struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"`
}

func (s *Subscription) parse(userinfo string) {
	s.Upload = 0
	s.Download = 0
	s.Total = 0
	s.Expire = 0

	// Subscription-Userinfo:
	// upload=2859205172; download=319670653638; total=322122547200; expire=1711870550
	parts := strings.Split(textproto.TrimString(userinfo), ";")
	if len(parts) == 1 && parts[0] == "" {
		return
	}

	for i := 0; i < len(parts); i++ {
		parts[i] = textproto.TrimString(parts[i])
		key, value, ok := strings.Cut(parts[i], "=")
		if !ok {
			continue
		}

		val, err := strconv.ParseInt(textproto.TrimString(value), 10, 64)
		if err != nil {
			continue
		}

		key = textproto.TrimString(key)
		switch key {
		case "upload":
			s.Upload = val
		case "download":
			s.Download = val
		case "total":
			s.Total = val
		case "expire":
			s.Expire = val
		}
	}
}
