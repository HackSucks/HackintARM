package osversion

import (
	"errors"
	"fmt"
)

// ErrMacOSProfile means no explicit macOS profile exists for a product version.
// It never selects a nearest release or silently falls back to the newest one.
var ErrMacOSProfile = errors.New("unqualified macOS compatibility profile")

// MacOSProfile identifies a compatibility target, not a claim that every
// framework feature has been qualified for that release. Feature packages must
// select behavior from their own native evidence and retain minor/patch versions
// when a behavior changes within a major release.
type MacOSProfile uint16

const (
	MacOS15 MacOSProfile = 15
	MacOS26 MacOSProfile = 26
	MacOS27 MacOSProfile = 27
)

// ProfileForMacOS selects an explicit target using a macOS product version.
// The same supplied version selects the same profile on Linux, macOS and Windows.
func ProfileForMacOS(v Version) (MacOSProfile, error) {
	switch v.Major {
	case 15:
		return MacOS15, nil
	case 26:
		return MacOS26, nil
	case 27:
		return MacOS27, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrMacOSProfile, v)
	}
}
