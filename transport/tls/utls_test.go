package tls

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"reflect"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"

	"github.com/yaling888/quirktiva/common/util"
)

func TestUConn_ConnectionState(t *testing.T) {
	cs := tls.ConnectionState{}
	type args struct {
		field  reflect.Value
		value  any
		value2 func(label string, context []byte, length int) ([]byte, error)
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "1",
			args: args{
				field: reflect.ValueOf(&cs).Elem().FieldByName("ekm"),
				value: reflect.ValueOf(&utls.ConnectionState{}).Elem().FieldByName("ekm"),
				value2: func(label string, context []byte, length int) ([]byte, error) {
					return []byte("cc ekm"), nil
				},
			},
			want:    "cc ekm",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := util.SetUnexportedField(tt.args.field, tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("SetUnexportedField() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := util.SetUnexportedField(tt.args.field, tt.args.value2); (err != nil) != tt.wantErr {
				t.Errorf("SetUnexportedField() error = %v, wantErr %v", err, tt.wantErr)
			}
			got, err := cs.ExportKeyingMaterial("", nil, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("cs.ExportKeyingMaterial() error = %v, wantErr %v", err, tt.wantErr)
			}
			if string(got) != tt.want {
				t.Errorf("cs.ExportKeyingMaterial() got = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestUConn_ConnectionState1(t *testing.T) {
	type fields struct {
		UConn *utls.UConn
		Cfg   *utls.Config
	}
	tests := []struct {
		name    string
		fields  fields
		want    tls.ConnectionState
		wantErr bool
	}{
		{
			name: "1",
			fields: fields{
				UConn: &utls.UConn{Conn: &utls.Conn{}},
				Cfg:   &utls.Config{ServerName: "example.com"},
			},
			want: tls.ConnectionState{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := UConn{
				UConn: tt.fields.UConn,
			}
			target := reflect.ValueOf(tt.fields.UConn.Conn).Elem().FieldByName("config")
			if err := util.SetUnexportedField(target, tt.fields.Cfg); (err != nil) != tt.wantErr {
				t.Errorf("SetUnexportedField() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			_ = u.ConnectionState()
		})
	}
}

func Test_wrapUTLSConfig(t *testing.T) {
	type args struct {
		c *tls.Config
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   []utls.Certificate
		want2   string
		wantErr bool
	}{
		{
			name: "1",
			args: args{
				c: &tls.Config{
					ServerName: "a",
					GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
						return &tls.Config{
							ServerName: "b",
							GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
								return &tls.Config{
									ServerName: "c",
								}, nil
							},
						}, nil
					},
				},
			},
			want:  "a",
			want1: nil,
			want2: "b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapUTLSConfig(tt.args.c)
			if got.ServerName != tt.want {
				t.Errorf("wrapUTLSConfig() = %v, want %v", got, tt.want)
				return
			}
			if !reflect.DeepEqual(got.Certificates, tt.want1) {
				t.Errorf("got.Certificates = %v, want %v", got.Certificates, tt.want1)
			}
			got1, err := got.GetConfigForClient(&utls.ClientHelloInfo{})
			if (err != nil) != tt.wantErr {
				t.Errorf("got.GetConfigForClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got1.ServerName != tt.want2 {
				t.Errorf("got1.ServerName = %v, want %v", got.ServerName, tt.want2)
			}
		})
	}
}

func TestStreamConnWithNextProtos(t *testing.T) {
	type args struct {
		isECH       bool
		fingerprint string
		nextProtos  []string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "TLS",
			args: args{
				isECH:       false,
				fingerprint: "",
				nextProtos:  []string{"h2", "http/1.1"},
			},
			want:    []string{"h2", "http/1.1"},
			wantErr: false,
		},
		{
			name: "TLS-ECH",
			args: args{
				isECH:       true,
				fingerprint: "",
				nextProtos:  []string{"h3", "h2"},
			},
			want:    []string{"h3", "h2"},
			wantErr: false,
		},
		{
			name: "uTLS",
			args: args{
				isECH:       false,
				fingerprint: "firefox",
			},
			want:    []string{"h2", "http/1.1"},
			wantErr: false,
		},
		{
			name: "uTLS-ECH",
			args: args{
				isECH:       true,
				fingerprint: "chrome",
			},
			wantErr: false,
		},
		{
			name: "uTLS-Alpn",
			args: args{
				isECH:       false,
				fingerprint: "firefox",
				nextProtos:  []string{"http/1.1"},
			},
			want:    []string{"http/1.1"},
			wantErr: false,
		},
		{
			name: "uTLS-ECH-Alpn",
			args: args{
				isECH:       true,
				fingerprint: "firefox",
				nextProtos:  []string{"example"},
			},
			want:    []string{"example"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(*testing.T) {
				srvConn, cliConn := net.Pipe()
				defer cliConn.Close()
				defer srvConn.Close()

				cliConfig, srvConfig, err := getTLSConfig(tt.args.isECH)
				if (err != nil) != tt.wantErr {
					t.Errorf("getTLSConfig() error = %v, wantErr %v", err, tt.wantErr)
					return
				}

				go func() {
					srvConfig.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
						if !slices.Equal(info.SupportedProtos, tt.want) {
							t.Errorf("srvConfig.SupportedProtos = %v, want %v", info.SupportedProtos, tt.want)
						}
						return nil, nil
					}
					srvTLSConn := tls.Server(srvConn, srvConfig)
					if err := srvTLSConn.Handshake(); (err != nil) != tt.wantErr {
						t.Errorf("srvTLSConn.Handshake() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
					_ = srvTLSConn.Close()
				}()

				cliConfig.NextProtos = tt.args.nextProtos
				cliTLSConn, err := StreamConnWithNextProtos(cliConn, cliConfig, tt.args.fingerprint, tt.args.nextProtos)
				synctest.Wait()
				if (err != nil) != tt.wantErr {
					t.Errorf("StreamConn() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				_ = cliTLSConn.Close()
			})
		})
	}
}

func getTLSConfig(isECH bool) (clientConfig, serverConfig *tls.Config, err error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"public.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	publicCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		return nil, nil, err
	}
	publicCert, err := x509.ParseCertificate(publicCertDER)
	if err != nil {
		return nil, nil, err
	}
	tmpl.DNSNames[0] = "secret.example"
	secretCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		return nil, nil, err
	}
	secretCert, err := x509.ParseCertificate(secretCertDER)
	if err != nil {
		return nil, nil, err
	}

	clientConfig, serverConfig = &tls.Config{}, &tls.Config{}
	clientConfig.InsecureSkipVerify = false
	clientConfig.Time = nil
	clientConfig.MinVersion = tls.VersionTLS12
	clientConfig.ServerName = "secret.example"
	clientConfig.RootCAs = x509.NewCertPool()
	clientConfig.RootCAs.AddCert(secretCert)
	clientConfig.RootCAs.AddCert(publicCert)
	serverConfig.InsecureSkipVerify = false
	serverConfig.Time = nil
	serverConfig.MinVersion = tls.VersionTLS12
	serverConfig.ServerName = "public.example"
	serverConfig.Certificates = []tls.Certificate{
		{Certificate: [][]byte{publicCertDER}, PrivateKey: k},
		{Certificate: [][]byte{secretCertDER}, PrivateKey: k},
	}

	if isECH {
		marshalECHConfig := func(id uint8, pubKey []byte, publicName string, maxNameLen uint8) []byte {
			builder := cryptobyte.NewBuilder(nil)
			builder.AddUint16(0xfe0d)
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddUint8(id)
				builder.AddUint16(0x0020 /* DHKEM(X25519, HKDF-SHA256) */)
				builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
					builder.AddBytes(pubKey)
				})
				builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
					builder.AddUint16(0x0001 /* HKDF-SHA256 */)
					builder.AddUint16(0x0001 /* AES-128-GCM */)
				})
				builder.AddUint8(maxNameLen)
				builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
					builder.AddBytes([]byte(publicName))
				})
				builder.AddUint16(0) // extensions
			})

			return builder.BytesOrPanic()
		}

		echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		echConfig := marshalECHConfig(123, echKey.PublicKey().Bytes(), "public.example", 32)

		builder := cryptobyte.NewBuilder(nil)
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes(echConfig)
		})
		echConfigList := builder.BytesOrPanic()

		clientConfig.EncryptedClientHelloConfigList = echConfigList
		serverConfig.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{
			{Config: echConfig, PrivateKey: echKey.Bytes(), SendAsRetry: true},
		}

		clientConfig.MinVersion = tls.VersionTLS13
		serverConfig.MinVersion = tls.VersionTLS13
	}

	return clientConfig, serverConfig, nil
}
