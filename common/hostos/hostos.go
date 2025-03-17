//go:build unix

package hostos

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Version represents a semantic version of the form "%d.%d[.%d]".
type Version struct {
	major, minor int
}

// AtLeast returns whether vr is at least version major.minor.
func (vr Version) AtLeast(major, minor int) bool {
	return vr.major >= major && vr.minor >= minor
}

// LessThan returns whether vr is less than version major.minor.
func (vr Version) LessThan(major, minor int) bool {
	return !vr.AtLeast(major, minor)
}

func (vr Version) IsValid() bool {
	return vr.major != 0 || vr.minor != 0
}

func (vr Version) String() string {
	return fmt.Sprintf("v%d.%d", vr.major, vr.minor)
}

// KernelVersion returns the version of the kernel using uname(),
// or (0, 0) if the version can't be obtained or parsed.
func KernelVersion() Version {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return Version{}
	}

	var (
		values    [2]int
		value, vi int
	)
	for _, c := range uname.Release {
		if '0' <= c && c <= '9' {
			value = (value * 10) + int(c-'0')
		} else {
			// Note that we're assuming N.N.N here.
			// If we see anything else, we are likely to mis-parse it.
			values[vi] = value
			vi++
			if vi >= len(values) {
				break
			}
			value = 0
		}
	}
	return Version{
		major: values[0],
		minor: values[1],
	}
}
