package util

import (
	"reflect"
	"testing"
)

func TestSetUnexportedField(t *testing.T) {
	type obj struct {
		x int
		z *int
	}
	type args struct {
		field  obj
		valueX any
		valueZ any
	}
	tests := []struct {
		name    string
		args    args
		wantX   any
		wantZ   *int
		wantErr bool
	}{
		{
			name: "1",
			args: args{
				field:  obj{x: 1, z: nil},
				valueX: 2,
				valueZ: new(3),
			},
			wantX:   2,
			wantZ:   new(3),
			wantErr: false,
		},
		{
			name: "2",
			args: args{
				field:  obj{x: 1, z: nil},
				valueX: uint(2),
				valueZ: nil,
			},
			wantX:   1,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := reflect.ValueOf(&tt.args.field).Elem().FieldByName("x")
			if err := SetUnexportedField(x, tt.args.valueX); (err != nil) != tt.wantErr {
				t.Errorf("SetUnexportedField() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got := tt.args.field.x; got != tt.wantX {
				t.Errorf("SetUnexportedField() gotX = %v, want %v", got, tt.wantX)
			}
			z := reflect.ValueOf(&tt.args.field).Elem().FieldByName("z")
			if err := SetUnexportedField(z, tt.args.valueZ); (err != nil) != tt.wantErr {
				t.Errorf("SetUnexportedField() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got := tt.args.field.z; got != nil && tt.args.field.z != nil && *got != *tt.args.field.z {
				t.Errorf("SetUnexportedField() gotZ = %v, want %v", got, tt.wantZ)
			}
		})
	}
}
