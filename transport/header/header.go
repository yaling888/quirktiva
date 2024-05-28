package header

import (
	"fmt"
	"strings"

	"github.com/yaling888/quirktiva/transport/header/dtls"
	"github.com/yaling888/quirktiva/transport/header/srtp"
	"github.com/yaling888/quirktiva/transport/header/utp"
	"github.com/yaling888/quirktiva/transport/header/wechat"
	"github.com/yaling888/quirktiva/transport/header/wireguard"
)

type Header interface {
	Size() int
	Fill(b []byte)
}

// New supports name "none" | "srtp" | "utp" | "dtls" | "wechat-video" | "wireguard",
// returns "nil, nil" if name is "none"
func New(name string) (Header, error) {
	switch strings.ToLower(name) {
	case "", "none":
		return nil, nil
	case "srtp":
		return srtp.New(), nil
	case "utp":
		return utp.New(), nil
	case "dtls":
		return dtls.New(), nil
	case "wechat-video":
		return wechat.New(), nil
	case "wireguard":
		return wireguard.New(), nil
	default:
		return nil, fmt.Errorf("unsupported obfs: %s", name)
	}
}
