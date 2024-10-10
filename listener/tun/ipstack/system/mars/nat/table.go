package nat

import (
	"net/netip"
	"sync"

	"github.com/yaling888/quirktiva/common/generics/list"
)

const (
	portBegin  uint16 = 30000
	portLength uint16 = 10240
)

var zeroTuple = tuple{}

type tuple struct {
	SourceAddr      netip.AddrPort
	DestinationAddr netip.AddrPort
}

type binding struct {
	tuple  tuple
	offset uint16
}

type table struct {
	tuples    map[tuple]*list.Element[*binding]
	ports     []*list.Element[*binding]
	available *list.List[*binding]
	mux       sync.Mutex
}

func (t *table) tupleOf(port uint16) tuple {
	offset := port - portBegin
	if offset >= portLength {
		return zeroTuple
	}

	elm := t.ports[offset]

	return elm.Value.tuple
}

func (t *table) portOf(tuple tuple) uint16 {
	t.mux.Lock()
	elm := t.tuples[tuple]
	t.mux.Unlock()
	if elm == nil {
		return 0
	}

	t.available.MoveToFront(elm)

	return portBegin + elm.Value.offset
}

func (t *table) newConn(tuple tuple) uint16 {
	elm := t.available.Back()
	b := elm.Value

	t.mux.Lock()
	delete(t.tuples, b.tuple)
	t.tuples[tuple] = elm
	b.tuple = tuple
	t.mux.Unlock()

	t.available.MoveToFront(elm)

	return portBegin + b.offset
}

func newTable() *table {
	result := &table{
		tuples:    make(map[tuple]*list.Element[*binding], portLength),
		ports:     make([]*list.Element[*binding], portLength),
		available: list.New[*binding](),
	}

	for idx := uint16(0); idx < portLength; idx++ {
		result.ports[idx] = result.available.PushFront(&binding{
			tuple:  tuple{},
			offset: idx,
		})
	}

	return result
}
