package pipe

import (
	"testing"
)

func TestBufferPipe(t *testing.T) {
	type args struct {
		buf  []byte
		data []byte
	}
	tests := []struct {
		name     string
		args     args
		wantN    int
		wantN1   int
		wantErr  bool
		wantErr1 bool
	}{
		{
			name: "read",
			args: args{
				data: []byte{1, 2, 3, 4, 5},
				buf:  make([]byte, 3),
			},
			wantN:    3,
			wantN1:   2,
			wantErr:  false,
			wantErr1: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, w := BufferPipe(6)
			defer r.Close()
			_, _ = w.Write(tt.args.data)
			gotN, err := r.Read(tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(tt.args.buf[:gotN]) != string(tt.args.data[:gotN]) {
				t.Errorf("Read() gotN = %v, want %v", tt.args.buf[:gotN], tt.args.data[:gotN])
			}
			if gotN != tt.wantN {
				t.Errorf("Read() gotN = %v, want %v", gotN, tt.wantN)
			}
			gotN1, err := r.Read(tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotN1 != tt.wantN1 {
				t.Errorf("Read() gotN1 = %v, want1 %v", gotN, tt.wantN)
			}
			if string(tt.args.buf[:gotN1]) != string(tt.args.data[len(tt.args.data)-gotN1:]) {
				t.Errorf("Read() gotN1 = %v, want1 %v", tt.args.buf[:gotN1], tt.args.data[len(tt.args.data)-gotN1:])
			}
			_ = w.Close()
			_, err = r.Read(tt.args.buf)
			if (err != nil) != tt.wantErr1 {
				t.Errorf("Read() error = %v, wantErr1 %v", err, tt.wantErr1)
				return
			}
		})
	}
}
