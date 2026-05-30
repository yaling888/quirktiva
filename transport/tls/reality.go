package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	C "github.com/yaling888/quirktiva/constant"
)

type RealityConfig struct {
	ClientHelloID utls.ClientHelloID
	PublicKey     *ecdh.PublicKey
	ShortID       [8]byte
}

func StreamRealityConn(conn net.Conn, tlsConfig *tls.Config, realityConfig *RealityConfig) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
	defer cancel()
	return realityClientHandshake(ctx, conn, tlsConfig, realityConfig)
}

func realityClientHandshake(ctx context.Context, conn net.Conn, tlsConfig *tls.Config, realityConfig *RealityConfig) (net.Conn, error) {
	verifier := &realityVerifier{
		serverName: tlsConfig.ServerName,
	}
	uConfig := &utls.Config{
		ServerName:             tlsConfig.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  verifier.VerifyPeerCertificate,
	}
	uConn := utls.UClient(conn, uConfig, realityConfig.ClientHelloID)
	verifier.UConn = uConn
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	for _, extension := range uConn.Extensions {
		if ce, ok := extension.(*utls.SupportedCurvesExtension); ok {
			ce.Curves = slices.DeleteFunc(ce.Curves, func(curveID utls.CurveID) bool {
				return curveID == utls.X25519MLKEM768
			})
		}
		if ks, ok := extension.(*utls.KeyShareExtension); ok {
			ks.KeyShares = slices.DeleteFunc(ks.KeyShares, func(share utls.KeyShare) bool {
				return share.Group == utls.X25519MLKEM768
			})
		}
	}

	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}

	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				break
			}
		}
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)

	var nowTime time.Time
	if uConfig.Time != nil {
		nowTime = uConfig.Time()
	} else {
		nowTime = time.Now()
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(nowTime.Unix()))

	hello.SessionId[0] = 1
	hello.SessionId[1] = 8
	hello.SessionId[2] = 1
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], realityConfig.ShortID[:])
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil {
		return nil, errors.New("nil keyShareKeys")
	}
	ecdheKey := keyShareKeys.Ecdhe
	if ecdheKey == nil {
		ecdheKey = keyShareKeys.MlkemEcdhe
		if ecdheKey == nil {
			return nil, errors.New("nil ecdheKey")
		}
	}
	authKey, err := ecdheKey.ECDH(realityConfig.PublicKey)
	if err != nil {
		return nil, err
	}
	if authKey == nil {
		return nil, errors.New("nil authKey")
	}
	verifier.authKey = authKey
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	if err != nil {
		return nil, err
	}
	var aesCipher cipher.AEAD
	if aesgcmPreferred(hello.CipherSuites) {
		aesBlock, _ := aes.NewCipher(authKey)
		aesCipher, _ = cipher.NewGCM(aesBlock)
	} else {
		aesCipher, _ = chacha20poly1305.New(authKey)
	}
	aesCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if err = uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	if !verifier.verified {
		go realityClientFallback(uConn, uConfig.ServerName, realityConfig.ClientHelloID)
		return nil, errors.New("reality verification failed")
	}

	return uConn, nil
}

//go:linkname aesgcmPreferred github.com/refraction-networking/utls.aesgcmPreferred
func aesgcmPreferred(_ []uint16) bool

func realityClientFallback(uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer func() {
		_ = uConn.Close()
	}()
	client := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return uConn, nil
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       10 * time.Second,
			TLSHandshakeTimeout:   8 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: 8 * time.Second,
	}
	request, _ := http.NewRequest(http.MethodGet, "https://"+serverName, nil)
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", rand.IntN(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

func (c *realityVerifier) VerifyPeerCertificate(_ [][]byte, _ [][]*x509.Certificate) error {
	p, _ := reflect.TypeFor[utls.Conn]().FieldByName("peerCertificates")
	certs := *(*[]*x509.Certificate)(unsafe.Add(unsafe.Pointer(c.Conn), p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

func GetFingerprint(s string) utls.ClientHelloID {
	switch strings.ToLower(s) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "chrome":
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
	default:
		return utls.HelloChrome_120
	}
}
