package apfsversion

import "fmt"

// Verdict is what the ledger can say about mounting an image natively on a
// given host driver.
type Verdict int

const (
	// Unknown means this combination has not been exercised; callers that
	// cannot afford a wedged host should treat it as a refusal.
	Unknown Verdict = iota
	// Supported means the combination has been exercised and is safe.
	Supported
	// KnownDeadlock means the host driver is known to deadlock on this image.
	KnownDeadlock
)

func (v Verdict) String() string {
	switch v {
	case Supported:
		return "supported"
	case KnownDeadlock:
		return "known-deadlock"
	default:
		return "unknown"
	}
}

// Stable codes for machine-readable records and error messages.
const (
	CodeUnicodeNames  = "APFS-NATIVE-UNICODE-NAMES"
	CodeNewerWriter   = "APFS-NATIVE-NEWER-WRITER"
	CodeSupported     = "APFS-NATIVE-SUPPORTED"
	CodeUnknownSeries = "APFS-NATIVE-UNKNOWN-SERIES"
)

// Image carries the stamps read from one APFS image and, when the caller
// inspected the directory tree, how many stored names the host cannot
// represent. NamesInspected distinguishes "none found" from "not checked".
type Image struct {
	FormattedBy    Stamp
	LastModifiedBy Stamp
	NewestMounted  Version
	// UnrepresentableNames counts stored names the host's Unicode tables
	// reject (the host returns EILSEQ when asked to create them).
	UnrepresentableNames int
	NamesInspected       bool
}

// NewestWriter returns the newest Apple build version among the image's
// stamps, or an empty version when none is Apple's.
func (i Image) NewestWriter() Version {
	var newest Version
	for _, v := range []Version{i.FormattedBy.Version, i.LastModifiedBy.Version, i.NewestMounted} {
		if !v.IsZero() && (newest.IsZero() || v.Compare(newest) > 0) {
			newest = v
		}
	}
	return newest
}

// Assessment is the ledger's answer for one host and image.
type Assessment struct {
	Verdict Verdict
	Code    string
	Reason  string
}

// Error returns a non-nil error for any verdict other than Supported, so a
// caller can write `if err := a.Error(); err != nil`.
func (a Assessment) Error() error {
	if a.Verdict == Supported {
		return nil
	}
	return &MountError{Assessment: a}
}

// MountError is the error form of a non-supported Assessment.
type MountError struct{ Assessment Assessment }

func (e *MountError) Error() string {
	return fmt.Sprintf("apfsversion: native mount %s (%s): %s", e.Assessment.Verdict, e.Assessment.Code, e.Assessment.Reason)
}

// AssessNativeMount decides whether host, an APFS driver build version, may
// mount image natively.
//
// Evidence (go-apfs CI, 2026-10-06/07, macOS 15.7.9 receiver, APFS 2332):
//   - 6 of 6 mounts of a volume containing 28 Unicode 16 case-pair names
//     stored by macOS 27 deadlocked the kernel, whether the stamps read 3288
//     or were rewritten to 2332;
//   - 0 of 14 mounts of ASCII-only volumes deadlocked, including a macOS 15
//     volume restamped as 3288 and a macOS 27 volume restamped as 2332;
//   - macOS 26 and 27 receivers read every image without incident.
//
// So a host below the macOS 26 series must not mount a volume holding names
// it cannot represent; version stamps alone are not a reason to refuse. When
// the caller did not inspect names and the image was written by a newer
// driver than the host, the verdict is Unknown: names may be present.
func AssessNativeMount(host Version, image Image) Assessment {
	hostMajor, _, ok := MacOSMajor(host.Series())
	if !ok {
		return Assessment{Unknown, CodeUnknownSeries, fmt.Sprintf("host APFS version %q is outside the ledger", host)}
	}
	if image.NamesInspected && image.UnrepresentableNames > 0 && hostMajor == 15 {
		return Assessment{KnownDeadlock, CodeUnicodeNames, fmt.Sprintf("%d stored names are unrepresentable on the host; the macOS 15 APFS driver (series %d) deadlocks reading them", image.UnrepresentableNames, host.Series())}
	}
	if image.NamesInspected {
		return Assessment{Supported, CodeSupported, "every stored name is representable on the host"}
	}
	if newest := image.NewestWriter(); !newest.IsZero() && newest.Series() > host.Series() && hostMajor == 15 {
		return Assessment{Unknown, CodeNewerWriter, fmt.Sprintf("image written by APFS %s, newer than host %s, and stored names were not inspected", newest, host)}
	}
	return Assessment{Supported, CodeSupported, "no newer writer than the host and no inspected names"}
}
