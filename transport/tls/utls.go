package tls

import (
	"context"
	"crypto/tls"
	"maps"
	"net"
	"reflect"
	"slices"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/yaling888/quirktiva/common/util"
	C "github.com/yaling888/quirktiva/constant"
)

type connectionStater interface {
	ConnectionState() tls.ConnectionState
}

type handshaker interface {
	HandshakeContext(context.Context) error
}

type Conn interface {
	net.Conn
	NetConn() net.Conn
	connectionStater
	handshaker
}

var _ Conn = (*UConn)(nil)

type UConn struct {
	*utls.UConn
}

func (c *UConn) ConnectionState() tls.ConnectionState {
	return convertConnectionState(c.UConn.ConnectionState())
}

// StreamConn returns uTLS conn if fingerprint is present, otherwise returns go TLS conn.
func StreamConn(conn net.Conn, tlsConfig *tls.Config, fingerprint string) (c Conn, err error) {
	return StreamConnWithNextProtos(conn, tlsConfig, fingerprint, nil)
}

// StreamContextConn returns uTLS conn if fingerprint is present, otherwise returns go TLS conn.
func StreamContextConn(ctx context.Context, conn net.Conn, tlsConfig *tls.Config, fingerprint string) (c Conn, err error) {
	return StreamContextConnWithNextProtos(ctx, conn, tlsConfig, fingerprint, nil)
}

// StreamConnWithNextProtos Apply nextProtos if it's present.
// Returns uTLS conn if fingerprint is present. Otherwise, returns go TLS conn.
//
// It is not recommended to change the NextProtos in uTLS OuterClientHello, except websocket without ECH.
func StreamConnWithNextProtos(conn net.Conn, tlsConfig *tls.Config, fingerprint string, nextProtos []string) (c Conn, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	return StreamContextConnWithNextProtos(ctx, conn, tlsConfig, fingerprint, nextProtos)
}

// StreamContextConnWithNextProtos Apply nextProtos if it's present.
// Returns uTLS conn if fingerprint is present. Otherwise, returns go TLS conn.
//
// It is not recommended to change the NextProtos in uTLS OuterClientHello, except websocket without ECH.
func StreamContextConnWithNextProtos(ctx context.Context, conn net.Conn, tlsConfig *tls.Config, fingerprint string, nextProtos []string) (c Conn, err error) {
	if fingerprint != "" {
		uCfg := wrapUTLSConfig(tlsConfig)
		uConn := utls.UClient(conn, uCfg, getFingerprint(fingerprint))
		if len(nextProtos) != 0 {
			if uCfg.EncryptedClientHelloConfigList != nil {
				uCfg.NextProtos = nextProtos
			} else {
				if err = uConn.BuildHandshakeState(); err != nil {
					return nil, err
				}
				for _, ext := range uConn.Extensions {
					if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
						alpnExt.AlpnProtocols = nextProtos
						break
					}
				}
			}
		}
		c = &UConn{UConn: uConn}
	} else {
		c = tls.Client(conn, tlsConfig)
	}
	err = c.HandshakeContext(ctx)
	return c, err
}

//nolint:staticcheck
func wrapUTLSConfig(c *tls.Config) *utls.Config {
	if c == nil {
		return nil
	}
	uCfg := &utls.Config{
		Rand: c.Rand,
		Time: c.Time,
		Certificates: slices.Collect(util.ValuesFuncMap(c.Certificates, func(c tls.Certificate) utls.Certificate {
			return *convertCertificate(&c)
		})),
		VerifyPeerCertificate:    c.VerifyPeerCertificate,
		RootCAs:                  c.RootCAs,
		NextProtos:               c.NextProtos,
		ServerName:               c.ServerName,
		ClientAuth:               utls.ClientAuthType(c.ClientAuth),
		ClientCAs:                c.ClientCAs,
		InsecureSkipVerify:       c.InsecureSkipVerify,
		CipherSuites:             c.CipherSuites,
		PreferServerCipherSuites: c.PreferServerCipherSuites,
		SessionTicketsDisabled:   c.SessionTicketsDisabled,
		SessionTicketKey:         c.SessionTicketKey,
		MinVersion:               c.MinVersion,
		MaxVersion:               c.MaxVersion,
		CurvePreferences: slices.Collect(util.ValuesFuncMap(c.CurvePreferences, func(e tls.CurveID) utls.CurveID {
			return utls.CurveID(e)
		})),
		DynamicRecordSizingDisabled:    c.DynamicRecordSizingDisabled,
		Renegotiation:                  utls.RenegotiationSupport(c.Renegotiation),
		KeyLogWriter:                   c.KeyLogWriter,
		EncryptedClientHelloConfigList: c.EncryptedClientHelloConfigList,
		EncryptedClientHelloKeys: slices.Collect(util.ValuesFuncMap(c.EncryptedClientHelloKeys, func(e tls.EncryptedClientHelloKey) utls.EncryptedClientHelloKey {
			return utls.EncryptedClientHelloKey{
				Config:      e.Config,
				PrivateKey:  e.PrivateKey,
				SendAsRetry: e.SendAsRetry,
			}
		})),
	}
	if c.NameToCertificate != nil {
		uCfg.NameToCertificate = maps.Collect(util.MapValuesFuncMap(c.NameToCertificate, func(k string, c *tls.Certificate) (string, *utls.Certificate) {
			return k, convertCertificate(c)
		}))
	}
	if c.GetCertificate != nil {
		uCfg.GetCertificate = func(i *utls.ClientHelloInfo) (*utls.Certificate, error) {
			cert, err := c.GetCertificate(convertClientHelloInfo(i))
			return convertCertificate(cert), err
		}
	}
	if c.GetClientCertificate != nil {
		uCfg.GetClientCertificate = func(i *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			info := &tls.CertificateRequestInfo{
				AcceptableCAs: i.AcceptableCAs,
				SignatureSchemes: slices.Collect(util.ValuesFuncMap(i.SignatureSchemes, func(s utls.SignatureScheme) tls.SignatureScheme {
					return tls.SignatureScheme(s)
				})),
				Version: i.Version,
			}
			cert, err := c.GetClientCertificate(info)
			return convertCertificate(cert), err
		}
	}
	if c.GetConfigForClient != nil {
		uCfg.GetConfigForClient = func(i *utls.ClientHelloInfo) (*utls.Config, error) {
			cert, err := c.GetConfigForClient(convertClientHelloInfo(i))
			return wrapUTLSConfig(cert), err
		}
	}
	//if c.GetEncryptedClientHelloKeys != nil {
	//	uCfg.GetEncryptedClientHelloKeys = func(i *utls.ClientHelloInfo) ([]utls.EncryptedClientHelloKey, error) {
	//		keys, err := c.GetEncryptedClientHelloKeys(convertClientHelloInfo(i))
	//		if err != nil {
	//			return nil, err
	//		}
	//		return slices.Collect(util.ValuesFuncMap(keys, func(e tls.EncryptedClientHelloKey) utls.EncryptedClientHelloKey {
	//			return utls.EncryptedClientHelloKey{
	//				Config:      e.Config,
	//				PrivateKey:  e.PrivateKey,
	//				SendAsRetry: e.SendAsRetry,
	//			}
	//		})), nil
	//	}
	//}
	if c.VerifyConnection != nil {
		uCfg.VerifyConnection = func(s utls.ConnectionState) error {
			return c.VerifyConnection(convertConnectionState(s))
		}
	}
	if c.EncryptedClientHelloRejectionVerify != nil {
		uCfg.EncryptedClientHelloRejectionVerify = func(s utls.ConnectionState) error {
			return c.EncryptedClientHelloRejectionVerify(convertConnectionState(s))
		}
	}
	return uCfg
}

func convertCertificate(c *tls.Certificate) *utls.Certificate {
	if c == nil {
		return nil
	}
	return &utls.Certificate{
		Certificate: c.Certificate,
		PrivateKey:  c.PrivateKey,
		SupportedSignatureAlgorithms: slices.Collect(util.ValuesFuncMap(c.SupportedSignatureAlgorithms, func(s tls.SignatureScheme) utls.SignatureScheme {
			return utls.SignatureScheme(s)
		})),
		OCSPStaple:                  c.OCSPStaple,
		SignedCertificateTimestamps: c.SignedCertificateTimestamps,
		Leaf:                        c.Leaf,
	}
}

func convertClientHelloInfo(i *utls.ClientHelloInfo) *tls.ClientHelloInfo {
	if i == nil {
		return nil
	}
	info := &tls.ClientHelloInfo{
		CipherSuites: i.CipherSuites,
		ServerName:   i.ServerName,
		SupportedCurves: slices.Collect(util.ValuesFuncMap(i.SupportedCurves, func(e utls.CurveID) tls.CurveID {
			return tls.CurveID(e)
		})),
		SupportedPoints: i.SupportedPoints,
		SignatureSchemes: slices.Collect(util.ValuesFuncMap(i.SignatureSchemes, func(s utls.SignatureScheme) tls.SignatureScheme {
			return tls.SignatureScheme(s)
		})),
		SupportedProtos:   i.SupportedProtos,
		SupportedVersions: i.SupportedVersions,
		Extensions:        i.Extensions,
		Conn:              i.Conn,
		// HelloRetryRequest: i.HelloRetryRequest,
	}
	//config := reflect.ValueOf(info).Elem().FieldByName("config")
	//_ = util.SetUnexportedField(config, reflect.ValueOf(i).Elem().FieldByName("config"))
	//isQUIC := reflect.ValueOf(info).Elem().FieldByName("isQUIC")
	//_ = util.SetUnexportedField(isQUIC, reflect.ValueOf(i).Elem().FieldByName("isQUIC"))
	//ctx := reflect.ValueOf(info).Elem().FieldByName("ctx")
	//_ = util.SetUnexportedField(ctx, reflect.ValueOf(i).Elem().FieldByName("ctx"))
	return info
}

//nolint:staticcheck
func convertConnectionState(s utls.ConnectionState) tls.ConnectionState {
	var state tls.ConnectionState
	state.Version = s.Version
	state.HandshakeComplete = s.HandshakeComplete
	state.DidResume = s.DidResume
	state.CipherSuite = s.CipherSuite
	//state.CurveID = tls.CurveID(s.CurveID)
	state.NegotiatedProtocol = s.NegotiatedProtocol
	state.NegotiatedProtocolIsMutual = s.NegotiatedProtocolIsMutual
	state.ServerName = s.ServerName
	state.PeerCertificates = s.PeerCertificates
	state.VerifiedChains = s.VerifiedChains
	state.SignedCertificateTimestamps = s.SignedCertificateTimestamps
	state.OCSPResponse = s.OCSPResponse
	state.TLSUnique = s.TLSUnique
	state.ECHAccepted = s.ECHAccepted
	//state.HelloRetryRequest = s.HelloRetryRequest
	//state.LocalCertificate = s.LocalCertificate
	target := reflect.ValueOf(&state).Elem().FieldByName("ekm")
	_ = util.SetUnexportedField(target, reflect.ValueOf(&s).Elem().FieldByName("ekm"))
	return state
}

func getFingerprint(s string) utls.ClientHelloID {
	switch strings.ToLower(s) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "chrome":
		return utls.HelloChrome_Auto
	case "chrome_120", "hellochrome_120":
		return utls.HelloChrome_120
	case "edge":
		return utls.HelloEdge_Auto
	case "safari":
		return utls.HelloSafari_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "qq", "qqbrowser":
		return utls.HelloQQ_Auto
	case "360", "360browser":
		return utls.Hello360_Auto
	case "rand", "random", "randomized":
		return utls.HelloRandomizedALPN
	default:
		return utls.HelloFirefox_Auto
	}
}
