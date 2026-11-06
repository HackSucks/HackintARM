package hostdata

import "errors"

func (r *StatCopyResult) copyFlags(flags, preserve uint32, backend StatCopyBackend) {
	current, err := backend.ReadFlags()
	r.failure("read-flags", err)
	if err != nil {
		return
	} // Preserve mask is always nonzero for CopyStat.
	for range 4 {
		actual, err := backend.CompareAndSwapFlags(current, flags|current&preserve)
		r.FlagComparisons++
		r.write("compare-flags", err)
		if err == nil {
			if actual == current {
				r.FlagsApplied = true
				return
			}
			current = actual
		} else if !errors.Is(err, ErrStatFlagsAgain) {
			break
		}
	}
	r.FlagsFallback = true
	err = backend.Chflags(flags | current&preserve)
	r.write("flags", err)
	r.FlagsApplied = err == nil
}
