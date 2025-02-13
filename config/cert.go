package config

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"os"
	"sync"
	"time"

	"github.com/phuslu/log"

	"github.com/yaling888/quirktiva/common/cert"
	C "github.com/yaling888/quirktiva/constant"
)

var GetCertConfig = sync.OnceValues(func() (*cert.Config, error) {
	if err := initCert(); err != nil {
		return nil, err
	}

	rootCACert, err := tls.LoadX509KeyPair(C.Path.RootCA(), C.Path.CAKey())
	if err != nil {
		return nil, err
	}

	privateKey, ok := rootCACert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, rsa.ErrVerification
	}

	x509c, err := x509.ParseCertificate(rootCACert.Certificate[0])
	if err != nil {
		return nil, err
	}

	certOption, err := cert.NewConfig(
		x509c,
		privateKey,
	)
	if err != nil {
		return nil, err
	}

	certOption.SetValidity(time.Hour * 24 * 365) // 1 year

	return certOption, nil
})

func initCert() error {
	if _, err := os.Stat(C.Path.RootCA()); os.IsNotExist(err) {
		log.Info().Msg("[Config] can't find mitm_ca.crt, start generate")
		err = cert.GenerateAndSave(C.Path.RootCA(), C.Path.CAKey())
		if err != nil {
			return err
		}
		log.Info().Msg("[Config] generated CA private key and CA certificate")
	}

	return nil
}
