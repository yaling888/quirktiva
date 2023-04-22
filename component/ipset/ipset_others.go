//go:build !linux

package ipset

import (
	"net/netip"
)

// Test Always return false in non-linux
func Test(_ string, _ netip.Addr) (bool, error) {
	return false, nil
}

// Verify Always pass in non-linux
func Verify(_ string) error {
	return nil
}
