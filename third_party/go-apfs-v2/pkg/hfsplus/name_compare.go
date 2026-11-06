package hfsplus

import "unicode/utf16"

// CompareNames compares POSIX pathname components using the observed volume's
// case-sensitivity. HFS normalization and UTF-16 catalog ordering are preserved;
// current Unicode case folding is deliberately not substituted for HFS rules.
// Comparison does not establish that either component is admissible on a host.
func CompareNames(a, b string, caseSensitive bool) int {
	return compareNameUnits(utf16.Encode([]rune(normalizeName(catalogName(a)))), utf16.Encode([]rune(normalizeName(catalogName(b)))), caseSensitive)
}

func compareNameUnits(a, b []uint16, caseSensitive bool) int {
	next := func(units []uint16, index *int) (uint16, bool) {
		for *index < len(units) {
			u := units[*index]
			*index++
			if caseSensitive {
				return u, true
			}
			if f, ok := foldUnit(u); ok {
				return f, true
			}
		}
		return 0, false
	}
	i, j := 0, 0
	for {
		a, oka := next(a, &i)
		b, okb := next(b, &j)
		if !oka || !okb {
			if oka {
				return 1
			}
			if okb {
				return -1
			}
			return 0
		}
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
	}
}
