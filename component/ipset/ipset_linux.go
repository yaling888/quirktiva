//go:build linux

package ipset

import (
	"net/netip"

	"github.com/vishvananda/netlink"
)

// Test whether the ip is in the set or not
func Test(setName string, ip netip.Addr) (bool, error) {
	return netlink.IpsetTest(setName, &netlink.IPSetEntry{
		IP: ip.AsSlice(),
	})
}

// Verify dumps a specific ipset to check if we can use the set normally
func Verify(setName string) error {
	_, err := netlink.IpsetList(setName)
	return err
}
