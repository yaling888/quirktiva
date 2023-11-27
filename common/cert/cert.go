package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"strings"
	"time"
)

const monthDur = 30 * 24 * time.Hour

type CertsStorage interface {
	Get(key string) (*tls.Certificate, bool)

	Set(key string, cert *tls.Certificate)
}

type Config struct {
	rootCA       *x509.Certificate
	rootKey      any
	ca           *x509.Certificate
	caPrivateKey *ecdsa.PrivateKey

	roots         *x509.CertPool
	intermediates *x509.CertPool

	privateKey *ecdsa.PrivateKey

	validity time.Duration

	certsStorage CertsStorage
}

func (c *Config) GetRootCA() *x509.Certificate {
	return c.rootCA
}

func (c *Config) SetValidity(validity time.Duration) {
	c.validity = validity
}

func (c *Config) NewTLSConfigForHost(hostname string) *tls.Config {
	tlsConfig := &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := clientHello.ServerName
			if host == "" {
				host = hostname
			}

			return c.GetOrCreateCert(host)
		},
		NextProtos: []string{"http/1.1"},
	}

	return tlsConfig
}

func (c *Config) GetOrCreateCert(hostname string, ips ...net.IP) (*tls.Certificate, error) {
	var leaf *x509.Certificate
	tlsCertificate, ok := c.certsStorage.Get(hostname)
	if ok {
		leaf = tlsCertificate.Leaf
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName:       hostname,
			Roots:         c.roots,
			Intermediates: c.intermediates,
		}); err == nil {
			return tlsCertificate, nil
		}
	}

	var (
		key          = hostname
		topHost      = hostname
		wildcardHost = "*." + hostname
		dnsNames     []string
	)

	if ip := net.ParseIP(hostname); ip != nil {
		ips = append(ips, ip)
	} else {
		parts := strings.Split(hostname, ".")
		l := len(parts)

		if leaf != nil {
			dnsNames = append(dnsNames, leaf.DNSNames...)
		}

		if l > 2 {
			topIndex := l - 2
			topHost = strings.Join(parts[topIndex:], ".")

			for i := topIndex; i > 0; i-- {
				wildcardHost = "*." + strings.Join(parts[i:], ".")

				if i == topIndex && (len(dnsNames) == 0 || dnsNames[0] != topHost) {
					dnsNames = append(dnsNames, topHost, wildcardHost)
				} else if !hasDnsNames(dnsNames, wildcardHost) {
					dnsNames = append(dnsNames, wildcardHost)
				}
			}
		} else {
			dnsNames = append(dnsNames, topHost, wildcardHost)
		}

		key = "+." + topHost
	}

	now := time.Now()
	if now.After(c.ca.NotAfter) {
		midCA, midPrivateKey, err := generateCert("Clash TLS Hybrid ECC SHA384 CA1", true, c.rootCA, c.rootKey)
		if err != nil {
			return nil, err
		}
		c.ca = midCA
		c.caPrivateKey = midPrivateKey.(*ecdsa.PrivateKey)
	}

	notAfter := now.AddDate(0, int(c.validity/monthDur+1), 0)
	if notAfter.After(c.ca.NotAfter) {
		notAfter = c.ca.NotAfter
	}

	serial, _ := rand.Prime(rand.Reader, 120)
	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         topHost,
			Organization:       []string{"Clash Proxy Services"},
			OrganizationalUnit: []string{"Clash Plus"},
		},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		NotBefore:             clearClock(now.AddDate(0, -1, 0)),
		NotAfter:              clearClock(notAfter),
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, c.privateKey.Public(), c.caPrivateKey)
	if err != nil {
		return nil, err
	}

	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	tlsCertificate = &tls.Certificate{
		Certificate: [][]byte{raw, c.ca.Raw, c.rootCA.Raw},
		PrivateKey:  c.privateKey,
		Leaf:        x509c,
	}

	c.certsStorage.Set(key, tlsCertificate)
	return tlsCertificate, nil
}

// GenerateAndSave generate CA private key and CA certificate and dump them to file
func GenerateAndSave(caPath string, caKeyPath string) error {
	ca, privateKey, err := generateCert("Clash Root CA", true, nil, nil)
	if err != nil {
		return err
	}

	caOut, err := os.OpenFile(caPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func(caOut *os.File) {
		_ = caOut.Close()
	}(caOut)

	if err = pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}); err != nil {
		return err
	}

	caKeyOut, err := os.OpenFile(caKeyPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func(caKeyOut *os.File) {
		_ = caKeyOut.Close()
	}(caKeyOut)

	err = pem.Encode(caKeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey.(*rsa.PrivateKey))})
	if err != nil {
		return err
	}

	return nil
}

func NewConfig(rootCA *x509.Certificate, rootPrivateKey any) (*Config, error) {
	midCA, midPrivateKey, err := generateCert("Clash TLS Hybrid ECC SHA384 CA1", true, rootCA, rootPrivateKey)
	if err != nil {
		return nil, err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCA)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(midCA)

	return &Config{
		rootCA:        rootCA,
		rootKey:       rootPrivateKey,
		ca:            midCA,
		caPrivateKey:  midPrivateKey.(*ecdsa.PrivateKey),
		privateKey:    privateKey,
		validity:      time.Hour,
		certsStorage:  NewDomainTrieCertsStorage(),
		roots:         roots,
		intermediates: intermediates,
	}, nil
}

func generateCert(cn string, isCA bool, parentCA *x509.Certificate, parentKey any) (*x509.Certificate, any, error) {
	var (
		privateKey any
		err        error
	)
	if isCA && parentCA == nil {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
	if err != nil {
		return nil, nil, err
	}

	publicKey := privateKey.(crypto.Signer).Public()

	serial, _ := rand.Prime(rand.Reader, 120)
	year, month, day := time.Now().Date()

	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         cn,
			Country:            []string{"US"},
			Organization:       []string{"Clash Trust Services"},
			OrganizationalUnit: []string{"clashplus.eu.org"},
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if parentCA == nil {
		tmpl.NotBefore = time.Date(year-2, month, day, 0, 0, 0, 0, time.UTC)
		tmpl.NotAfter = time.Date(year+23, month, day, 0, 0, 0, 0, time.UTC)
		parentCA = tmpl
	} else {
		now := time.Now()
		var notAfter time.Time
		if isCA {
			tmpl.MaxPathLenZero = true
			notAfter = now.AddDate(5, 6, 0)
		} else {
			notAfter = now.AddDate(1, 6, 0)
		}
		if notAfter.After(parentCA.NotAfter) {
			notAfter = parentCA.NotAfter
		}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		tmpl.NotBefore = clearClock(now.AddDate(0, -6, 0))
		tmpl.NotAfter = clearClock(notAfter)
	}

	if parentKey == nil {
		parentKey = privateKey
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, parentCA, publicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}

func hasDnsNames(dnsNames []string, hostname string) bool {
	for _, name := range dnsNames {
		if name == hostname {
			return true
		}
	}
	return false
}

func clearClock(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}
