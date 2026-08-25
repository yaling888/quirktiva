package sniffer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/cryptobyte"
)

func TestReadOnlyConn(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "1",
			args: args{
				b: []byte{
					0x6e, 0x62, 0xe5, 0x1a, 0x43, 0x26, 0xb0, 0xac, 0xf9,
					0xc2, 0x20, 0x8b, 0x90, 0xd0, 0x36, 0x72, 0x51, 0x7b,
					0x5c, 0x85, 0x85, 0xf2, 0x6a, 0x18, 0xb1, 0x27, 0xa6,
					0x5d, 0x9c, 0xe9, 0x6a, 0x12, 0x4e, 0x17, 0x3d, 0xe5,
					0xe9, 0xe3, 0xa1, 0x5, 0x7c, 0x9a, 0x9, 0x6, 0x4c,
					0x51, 0x1f, 0xd9, 0xc5, 0x6f, 0xf9,
				},
			},
			want: []byte{
				0x6e, 0x62, 0xe5, 0x1a, 0x43, 0x26, 0xb0, 0xac, 0xf9,
				0xc2, 0x20, 0x8b, 0x90, 0xd0, 0x36, 0x72, 0x51, 0x7b,
				0x5c, 0x85, 0x85, 0xf2, 0x6a, 0x18, 0xb1, 0x27, 0xa6,
				0x5d, 0x9c, 0xe9, 0x6a, 0x12, 0x4e, 0x17, 0x3d, 0xe5,
				0xe9, 0xe3, 0xa1, 0x5, 0x7c, 0x9a, 0x9, 0x6, 0x4c,
				0x51, 0x1f, 0xd9, 0xc5, 0x6f, 0xf9,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 1024)
			c1 := newFakeTestConn(bytes.NewReader(tt.args.b))
			readOnlyConn := StreamReadOnlyConn(c1)
			n, _ := readOnlyConn.Read(buf)
			if got := buf[:n]; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("readOnlyConn Read() = %v, want %v", got, tt.want)
			}
			originConn := readOnlyConn.UnreadConn()
			clear(buf)
			n, _ = originConn.Read(buf)
			if got := buf[:n]; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unreadConn Read() = %v, want %v", got, tt.want)
			}
		})
	}
}

type cConn struct {
	net.Conn
	b bytes.Buffer
	i int
}

func (c *cConn) Write(b []byte) (n int, err error) {
	c.i++
	// fmt.Printf("Write len: %d, idx: %d\n", len(b), c.i)
	c.b.Write(b)
	//if c.i == 1 {
	//fmt.Printf("%#v\n", b)
	//fmt.Printf("%#v\n", c.b.Bytes())
	//}
	return c.Conn.Write(b)
}

var _ net.PacketConn = (*pConn)(nil)

type pConn struct {
	net.Conn
}

var addr1 = &net.TCPAddr{
	IP:   net.ParseIP("127.0.0.1"),
	Port: 4321,
}

func (pc *pConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = pc.Read(p)
	addr = addr1
	return
}

func (pc *pConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return pc.Write(p)
}

func (pc *pConn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 1234,
	}
}

func (pc *pConn) SetReadBuffer(_ int) error  { return nil }
func (pc *pConn) SetWriteBuffer(_ int) error { return nil }

func TestQUICECH(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"public.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	publicCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	publicCert, err := x509.ParseCertificate(publicCertDER)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.DNSNames[0] = "secret.example"
	secretCertDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	secretCert, err := x509.ParseCertificate(secretCertDER)
	if err != nil {
		t.Fatal(err)
	}

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
		t.Fatal(err)
	}

	echConfig := marshalECHConfig(123, echKey.PublicKey().Bytes(), "public.example", 32)

	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(echConfig)
	})
	echConfigList := builder.BytesOrPanic()

	clientConfig, serverConfig := &tls.Config{}, &tls.Config{}
	clientConfig.InsecureSkipVerify = false
	clientConfig.Time = nil
	clientConfig.MinVersion = tls.VersionTLS13
	clientConfig.ServerName = "secret.example"
	clientConfig.RootCAs = x509.NewCertPool()
	clientConfig.RootCAs.AddCert(secretCert)
	clientConfig.RootCAs.AddCert(publicCert)
	clientConfig.EncryptedClientHelloConfigList = echConfigList
	serverConfig.InsecureSkipVerify = false
	serverConfig.Time = nil
	serverConfig.MinVersion = tls.VersionTLS13
	serverConfig.ServerName = "public.example"
	serverConfig.Certificates = []tls.Certificate{
		{Certificate: [][]byte{publicCertDER}, PrivateKey: k},
		{Certificate: [][]byte{secretCertDER}, PrivateKey: k},
	}
	serverConfig.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{
		{Config: echConfig, PrivateKey: echKey.Bytes(), SendAsRetry: true},
	}

	closed := false
	c, s := net.Pipe()
	cc := &cConn{Conn: c}
	cp, sp := &pConn{cc}, &pConn{s}

	l, err := quic.ListenEarly(sp, serverConfig, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	go func() {
		defer l.Close()
		for !closed {
			c, err := l.Accept(ctx1)
			if err != nil {
				return
			}
			// fmt.Printf("%s\n", c.ConnectionState().TLS.ServerName)
			go func() {
				defer c.CloseWithError(quic.ApplicationErrorCode(2), "")
				for !closed {
					_, err = c.AcceptUniStream(ctx1)
					if err != nil {
						// fmt.Printf("%#v\n", cc.b.Bytes())
						return
					}
				}
			}()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	qc, err := quic.Dial(ctx, cp, addr1, clientConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer qc.CloseWithError(quic.ApplicationErrorCode(1), "")

	us, err := qc.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	_ = us.Close()
	closed = true
	cancel1()
}
