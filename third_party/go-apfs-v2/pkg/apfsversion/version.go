// Package apfsversion reads and compares the version stamps that Apple's APFS
// implementation records on disk, and keeps an evidence ledger of which
// combinations of host driver and image content are known to be safe or
// unsafe to mount natively.
//
// Apple ships one APFS build series per macOS release (for example 2332 in
// macOS 15.5 to 15.7, 2811 in macOS 26.4 and later, 3288 in macOS 27.0). Each
// volume superblock records the tool that formatted it (apfs_formatted_by) and
// the last eight writers (apfs_modified_by), as "newfs_apfs (2811.160.7.0.4)"
// or "apfs_kext (2811.160.7.0.4)". Each container superblock records the
// newest driver that mounted it (nx_newest_mounted_version) as a packed
// integer. None of this is documented in Apple's 2020 APFS reference; the
// encodings here were derived from images produced on macOS 15, 26 and 27.
//
// The ledger is deliberately small and evidence-backed. Apple gates on-disk
// incompatibility with feature bits, and the one failure this package exists
// to prevent bypasses that mechanism entirely: a macOS 15 driver deadlocks the
// whole kernel's disk I/O when it reads a volume containing filenames that a
// newer kernel stored and that macOS 15's Unicode tables cannot normalize.
// The on-disk structures of such a volume are otherwise identical to what
// macOS 15 writes itself, so version stamps alone neither cause nor predict
// the failure; filename content does.
package apfsversion

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version is an APFS implementation build version, such as 2811.160.7.0.4.
// The first component is the build series shared by one macOS release.
type Version []int

// ErrInvalidVersion reports a string that is not a dotted sequence of
// non-negative integers.
var ErrInvalidVersion = errors.New("apfsversion: invalid version")

// Parse parses a dotted build version such as "3288.1.3".
func Parse(s string) (Version, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidVersion)
	}
	parts := strings.Split(s, ".")
	v := make(Version, 0, len(parts))
	for _, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') || len(p) > 9 {
			return nil, fmt.Errorf("%w: %q", ErrInvalidVersion, s)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%w: %q", ErrInvalidVersion, s)
		}
		v = append(v, n)
	}
	return v, nil
}

// MustParse is Parse for constants; it panics on an invalid version.
func MustParse(s string) Version {
	v, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}

// Series returns the build series (the first component), or 0 for an empty
// version.
func (v Version) Series() int {
	if len(v) == 0 {
		return 0
	}
	return v[0]
}

// String renders the dotted form; an empty version renders as "".
func (v Version) String() string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}

// Compare orders versions component by component, treating missing trailing
// components as zero. It returns -1, 0 or 1.
func (v Version) Compare(o Version) int {
	n := max(len(v), len(o))
	for i := 0; i < n; i++ {
		a, b := 0, 0
		if i < len(v) {
			a = v[i]
		}
		if i < len(o) {
			b = o[i]
		}
		if a != b {
			if a < b {
				return -1
			}
			return 1
		}
	}
	return 0
}

// IsZero reports an absent version.
func (v Version) IsZero() bool { return len(v) == 0 }

// Packed is the encoding of nx_newest_mounted_version in the container
// superblock: five components packed as a·10^12 + b·10^9 + c·10^6 + d·10^3 + e.
// Observed: 2332.140.13.702.2 is stored as 2332140013702002 and 3288.1.3 as
// 3288001003000000.
const (
	packedComponents = 5
	packedLimit      = 1000
)

// ErrPackedRange reports a version that cannot be packed because it has more
// than five components, a component of 1000 or more after the first, or a
// first component too large for the 64-bit field.
var ErrPackedRange = errors.New("apfsversion: version does not fit the packed encoding")

// packedSeriesLimit keeps a·10^12 + (10^12 - 1) within uint64.
const packedSeriesLimit = 18446744

// DecodePacked expands a packed nx_newest_mounted_version. Zero decodes to an
// empty Version, which is what a container never mounted read-write reports.
func DecodePacked(packed uint64) Version {
	if packed == 0 {
		return nil
	}
	v := make(Version, packedComponents)
	rest := packed
	for i := packedComponents - 1; i > 0; i-- {
		v[i] = int(rest % packedLimit)
		rest /= packedLimit
	}
	v[0] = int(rest)
	return v
}

// EncodePacked packs a version in the nx_newest_mounted_version encoding.
func EncodePacked(v Version) (uint64, error) {
	if len(v) > packedComponents {
		return 0, fmt.Errorf("%w: %s", ErrPackedRange, v)
	}
	var packed uint64
	for i := 0; i < packedComponents; i++ {
		n := 0
		if i < len(v) {
			n = v[i]
		}
		if n < 0 || (i > 0 && n >= packedLimit) || (i == 0 && n >= packedSeriesLimit) {
			return 0, fmt.Errorf("%w: %s", ErrPackedRange, v)
		}
		packed = packed*packedLimit + uint64(n)
	}
	return packed, nil
}
