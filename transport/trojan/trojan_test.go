package trojan

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"reflect"
	"testing"
)

type fakeConn struct {
	net.Conn
	rw *bytes.Buffer
}

func (f *fakeConn) Read(b []byte) (n int, err error) {
	return f.rw.Read(b)
}

func (f *fakeConn) Write(b []byte) (n int, err error) {
	return f.rw.Write(b)
}

func TestPacketConn_ReadFrom(t *testing.T) {
	srcS := make([]byte, 64*1025)
	srcL := make([]byte, 7*1024)
	_, _ = rand.Read(srcS)
	_, _ = rand.Read(srcL)

	addr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1").To4(),
		Port: 443,
	}

	type fields struct {
		Conn net.Conn
	}
	type args struct {
		src  []byte
		buf  []byte
		addr net.Addr
	}
	tests := []struct {
		name     string
		fields   fields
		args     args
		wantN    int
		wantAddr netip.AddrPort
		wantErr  bool
	}{
		{
			name: "smallBuffer",
			fields: fields{
				Conn: &fakeConn{
					rw: &bytes.Buffer{},
				},
			},
			args: args{
				src:  srcS,
				buf:  make([]byte, 1024),
				addr: addr,
			},
			wantN:    len(srcS),
			wantAddr: addr.AddrPort(),
			wantErr:  false,
		},
		{
			name: "largeBuffer",
			fields: fields{
				Conn: &fakeConn{
					rw: &bytes.Buffer{},
				},
			},
			args: args{
				src:  srcL,
				buf:  make([]byte, 32*1024),
				addr: addr,
			},
			wantN:    len(srcL),
			wantAddr: addr.AddrPort(),
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := &PacketConn{
				Conn: tt.fields.Conn,
			}
			gotN, err := pc.WriteTo(tt.args.src, tt.args.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN != tt.wantN {
				t.Errorf("WriteTo() gotN = %v, want %v", gotN, tt.wantN)
			}

			buf := tt.args.buf
			dst := make([]byte, 0, 64*1024)
			for {
				n, gotAddr, err1 := pc.ReadFrom(buf)
				if err1 != nil {
					if err1 == io.EOF {
						break
					} else if !tt.wantErr {
						t.Errorf("ReadFrom() error = %v, wantErr %v", err1, tt.wantErr)
						return
					}
				}
				if gotAddr.(*net.UDPAddr).AddrPort() != tt.wantAddr {
					t.Errorf("ReadFrom() gotAddr = %v, want %v", gotAddr, tt.wantAddr)
				}
				dst = append(dst, buf[:n]...)
			}

			if len(dst) != tt.wantN {
				t.Errorf("ReadFrom() read data doesn't match write data, gotN = %v, want %v", len(dst), tt.wantN)
				return
			}

			if !reflect.DeepEqual(dst, tt.args.src) {
				t.Errorf("ReadFrom() read data doesn't match write data")
			}
		})
	}
}
