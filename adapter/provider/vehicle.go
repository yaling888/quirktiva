package provider

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/yaling888/clash/common/convert"
	"github.com/yaling888/clash/component/dialer"
	"github.com/yaling888/clash/component/profile/cachefile"
	"github.com/yaling888/clash/constant"
	types "github.com/yaling888/clash/constant/provider"
	"github.com/yaling888/clash/listener/auth"
)

var _ types.Vehicle = (*FileVehicle)(nil)

type FileVehicle struct {
	path string
}

func (f *FileVehicle) Type() types.VehicleType {
	return types.File
}

func (f *FileVehicle) Path() string {
	return f.path
}

func (*FileVehicle) Proxy() bool {
	return false
}

func (f *FileVehicle) Read() ([]byte, error) {
	return os.ReadFile(f.path)
}

func NewFileVehicle(path string) *FileVehicle {
	return &FileVehicle{path: path}
}

var _ types.Vehicle = (*HTTPVehicle)(nil)

type HTTPVehicle struct {
	path         string
	url          string
	urlProxy     bool
	header       http.Header
	subscription *Subscription
}

func (h *HTTPVehicle) Type() types.VehicleType {
	return types.HTTP
}

func (h *HTTPVehicle) Path() string {
	return h.path
}

func (h *HTTPVehicle) Proxy() bool {
	return h.urlProxy
}

func (h *HTTPVehicle) Read() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	uri, err := url.Parse(h.url)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, err
	}

	if h.header != nil {
		req.Header = h.header
	}

	if user := uri.User; user != nil {
		password, _ := user.Password()
		req.SetBasicAuth(user.Username(), password)
	}

	convert.SetUserAgent(req.Header)

	req = req.WithContext(ctx)

	transport := &http.Transport{
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if h.urlProxy {
				// forward to tun if tun enabled
				// do not reject the Clash’s own traffic by rule `PROCESS-NAME`
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			return dialer.DialContext(ctx, network, address, dialer.WithDirect()) // with direct
		},
	}

	// fallback to proxy url if tun disabled, make sure enable at least one inbound port
	// do not reject the Clash’s own traffic by rule `PROCESS-NAME`
	if h.urlProxy && !constant.GetTunConf().Enable {
		transport.Proxy = constant.ProxyURL(auth.Authenticator())
	}

	client := http.Client{Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	userinfo := resp.Header.Get("Subscription-Userinfo")
	if userinfo != "" {
		if h.subscription == nil {
			h.subscription = &Subscription{}
		}
		h.subscription.parse(userinfo)
		if h.subscription.Total != 0 {
			cachefile.Cache().SetSubscription(h.url, userinfo)
		}
	}

	return removeComment(buf), nil
}

func (h *HTTPVehicle) Subscription() *Subscription {
	return h.subscription
}

func NewHTTPVehicle(path string, url string, urlProxy bool, header http.Header) *HTTPVehicle {
	var (
		userinfo     = cachefile.Cache().GetSubscription(url)
		subscription *Subscription
	)
	if userinfo != "" {
		subscription = &Subscription{}
		subscription.parse(userinfo)
	}
	return &HTTPVehicle{
		path:         path,
		url:          url,
		urlProxy:     urlProxy,
		header:       header,
		subscription: subscription,
	}
}

func removeComment(buf []byte) []byte {
	arr := regexp.MustCompile(`(.*#.*\n)`).FindAllSubmatch(buf, -1)
	for _, subs := range arr {
		sub := subs[0]
		if !bytes.HasPrefix(bytes.TrimLeft(sub, " 	"), []byte("#")) {
			continue
		}
		buf = bytes.Replace(buf, sub, []byte(""), 1)
	}
	return buf
}
