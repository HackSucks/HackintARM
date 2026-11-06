// Package osversion parses operating-system versions and identifies explicit
// macOS compatibility profiles independently of the operating system running Go.
package osversion

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrVersion reports a malformed numeric product version.
var ErrVersion = errors.New("invalid operating-system product version")

// Version is a product version, such as macOS 15.7. It is not a Darwin kernel
// release, SDK version, deployment target or build identifier.
type Version struct{ Major, Minor, Patch uint32 }

// Parse accepts one to three unsigned decimal components. Missing minor and
// patch components mean zero. Whitespace, signs and suffixes are not accepted.
func Parse(value string) (Version, error) {
	var v Version
	components := strings.Split(value, ".")
	if len(components) > 3 {
		return v, fmt.Errorf("%w: %q", ErrVersion, value)
	}
	numbers := [3]uint32{}
	for i, component := range components {
		if component == "" {
			return v, fmt.Errorf("%w: %q", ErrVersion, value)
		}
		for _, c := range component {
			if c < '0' || c > '9' {
				return v, fmt.Errorf("%w: %q", ErrVersion, value)
			}
		}
		n, err := strconv.ParseUint(component, 10, 32)
		if err != nil {
			return v, fmt.Errorf("%w: %q", ErrVersion, value)
		}
		numbers[i] = uint32(n)
	}
	if numbers[0] == 0 {
		return v, fmt.Errorf("%w: zero major version", ErrVersion)
	}
	return Version{numbers[0], numbers[1], numbers[2]}, nil
}

// String returns all three product-version components.
func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Compare returns -1, 0 or 1 according to numeric version ordering.
func (v Version) Compare(other Version) int {
	a, b := [3]uint32{v.Major, v.Minor, v.Patch}, [3]uint32{other.Major, other.Minor, other.Patch}
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// ParseProductVersion reads the single ProductVersion field in a sw_vers capture.
// It parses captured text on every host; it never executes sw_vers.
func ParseProductVersion(capture string) (Version, error) {
	var v Version
	found := false
	for _, line := range strings.Split(capture, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "ProductVersion:" {
			continue
		}
		if found || len(fields) != 2 {
			return Version{}, ErrVersion
		}
		var err error
		v, err = Parse(fields[1])
		if err != nil {
			return Version{}, err
		}
		found = true
	}
	if !found {
		return Version{}, ErrVersion
	}
	return v, nil
}
