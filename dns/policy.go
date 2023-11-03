package dns

import "reflect"

type Policy struct {
	data []dnsClient
}

func (p *Policy) GetData() []dnsClient {
	return p.data
}

func (p *Policy) Compare(p2 *Policy) int {
	if p == nil && p2 == nil {
		return 0
	}
	if p == nil || p2 == nil {
		return 1
	}
	if reflect.DeepEqual(p.data, p2.data) {
		return 0
	}
	if len(p.data) > len(p2.data) {
		return 1
	}
	return -1
}

func NewPolicy(data []dnsClient) *Policy {
	return &Policy{
		data: data,
	}
}
