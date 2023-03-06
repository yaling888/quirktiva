package device

import (
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Device is the interface that implemented by network layer devices (e.g. tun),
// and easy to use as stack.LinkEndpoint.
type Device interface {
	stack.LinkEndpoint

	// Name returns the current name of the device.
	Name() string

	// Type returns the driver type of the device.
	Type() string

	// Read one or more packets from the Device (without any additional headers).
	// On a successful read it returns the number of packets read, and sets
	// packet lengths within the sizes slice. len(sizes) must be >= len(buffs).
	// A nonzero offset can be used to instruct the Device on where to begin
	// reading into each element of the buffs slice.
	Read(buffs [][]byte, sizes []int, offset int) (n int, err error)

	// Write one or more packets to the device (without any additional headers).
	// On a successful write it returns the number of packets written. A nonzero
	// offset can be used to instruct the Device on where to begin writing from
	// each packet contained within the buffs slice.
	Write(buffs [][]byte, offset int) (int, error)

	// Close stops and closes the device.
	Close() error

	// UseEndpoint work for gVisor stack
	UseEndpoint() error

	// UseIOBased work for other ip stack
	UseIOBased() error

	// BatchSize returns the preferred/max number of packets that can be read or
	// written in a single read/write call. BatchSize must not change over the
	// lifetime of a Device.
	BatchSize() int

	Offset() int
}
