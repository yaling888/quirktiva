package constant

import (
	"crypto/tls"
	"net/http"

	"github.com/yaling888/quirktiva/common/cert"
)

const MitmApiHost = "mitm.clash"

type RewriteHandler interface {
	HandleRequest(rw http.ResponseWriter, req *http.Request) bool
	HandleResponse(res *http.Response) error
}

type MitmOption struct {
	ApiHost string

	TLSConfig  *tls.Config
	CertConfig *cert.Config

	Handler RewriteHandler
}
