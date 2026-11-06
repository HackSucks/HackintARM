package nameunicode

import "sort"

type scalarRange struct{ first, last rune }

// APFSCreateAllowed reports the actual target profile's scalar admission.
// The caller must validate the target profile and UTF-8/component boundaries.
func APFSCreateAllowed(r rune, major int) bool {
	var ranges []scalarRange
	switch major {
	case 15:
		ranges = apfsCreate15[:]
	case 26:
		ranges = apfsCreate26[:]
	case 27:
		ranges = apfsCreate27[:]
	default:
		return false
	}
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].last >= r })
	return i < len(ranges) && r >= ranges[i].first
}
