package nat

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/yaling888/quirktiva/common/generics/list"
)

func Test_nat_table(t *testing.T) {
	type args struct {
		tuple tuple
	}

	pl := uint16(10)
	tb := &table{
		tuples:    make(map[tuple]*list.Element[*binding], pl),
		ports:     make([]*list.Element[*binding], pl),
		available: list.New[*binding](),
	}

	for idx := uint16(0); idx < pl; idx++ {
		tb.ports[idx] = tb.available.PushFront(&binding{
			tuple:  tuple{},
			offset: idx,
		})
	}

	tests := [10]struct {
		name string
		args args
		want uint16
	}{}

	addr := netip.IPv4Unspecified()
	for i, tt := range tests {
		tt.name = fmt.Sprintf("test%d", i)
		tt.args.tuple = tuple{
			SourceAddr: netip.AddrPortFrom(addr, tt.want),
		}
		tt.want = portBegin + uint16(i)
		addr = addr.Next()
		t.Run(tt.name, func(t *testing.T) {
			if got := tb.newConn(tt.args.tuple); got != tt.want {
				t.Errorf("newConn() = %v, want %v", got, tt.want)
			}
			if got := tb.portOf(tt.args.tuple); got != tt.want {
				t.Errorf("portOf() = %v, want %v", got, tt.want)
			}
			if got := tb.tupleOf(tt.want); got != tt.args.tuple {
				t.Errorf("tupleOf() = %v, want %v", got, tt.args.tuple)
			}
		})
	}
}
