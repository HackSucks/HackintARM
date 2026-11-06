//go:build !darwin && !linux

package hostdata

import "sort"

// XattrsSupported reports whether this build can read extended attributes.
const XattrsSupported = false

// ListXattrs returns no attributes on a platform that has none this tool can
// read. It reports success rather than an error, because "there is nothing
// here" is the truth on such a platform, and a caller reporting fidelity loss
// should say attributes were unreadable, not that the walk failed.
func ListXattrs(path string) (map[string][]byte, error) {
	return map[string][]byte{}, nil
}

// SetXattrs writes nothing on a platform with no extended attributes, and
// reports every name as unwritten so the caller can say so rather than
// implying the attributes were restored.
func SetXattrs(path string, attrs map[string][]byte) (written int, failed []string) {
	for name := range attrs {
		failed = append(failed, name)
	}
	sort.Strings(failed)
	return 0, failed
}
