package apfsversion

// Release maps an APFS build series to the macOS releases that shipped it.
// Source names where each row came from; nothing here is published by Apple.
type Release struct {
	Series int
	MacOS  string
	Source string
}

const (
	sourceOakley   = "Howard Oakley, eclecticlight.co, APFS version numbers by release (2026)"
	sourceObserved = "observed in go-apfs CI producer images on GitHub-hosted runners, 2026-10-06"
)

// ledger lists the series this project has evidence for, newest last.
var ledger = []Release{
	{2313, "macOS 15.0 to 15.2", sourceOakley},
	{2317, "macOS 15.3 to 15.4", sourceOakley},
	{2332, "macOS 15.5 to 15.7", sourceOakley + "; " + sourceObserved + " (2332.140.13.702.2 on 15.7.9)"},
	{2632, "macOS 26.0 to 26.3", sourceOakley},
	{2811, "macOS 26.4 and later 26.x", sourceOakley + "; " + sourceObserved + " (2811.160.7.0.4 on macos-latest)"},
	{3288, "macOS 27.0", sourceOakley + "; " + sourceObserved + " (3288.1.3 on xcode-27)"},
}

// Releases returns a copy of the ledger.
func Releases() []Release { return append([]Release(nil), ledger...) }

// ReleaseForSeries returns the ledger row for an exact series.
func ReleaseForSeries(series int) (Release, bool) {
	for _, r := range ledger {
		if r.Series == series {
			return r, true
		}
	}
	return Release{}, false
}

// Series boundaries between macOS major releases. The 2600 boundary is the
// first macOS 26 series (2632); 3200 separates the 26.x series from macOS 27's
// 3288. Values between known rows are attributed by range, which is inference.
const (
	seriesMacOS15 = 2300
	seriesMacOS26 = 2600
	seriesMacOS27 = 3200
)

// MacOSMajor attributes a build series to a macOS major release. exact is
// true when the series is a ledger row rather than a range inference.
func MacOSMajor(series int) (major int, exact bool, ok bool) {
	_, exact = ReleaseForSeries(series)
	switch {
	case series >= seriesMacOS27:
		return 27, exact, true
	case series >= seriesMacOS26:
		return 26, exact, true
	case series >= seriesMacOS15:
		return 15, exact, true
	default:
		return 0, false, false
	}
}
