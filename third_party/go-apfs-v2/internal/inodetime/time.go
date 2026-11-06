// Package inodetime encodes explicitly selected inode timestamps for image writers.
package inodetime

import (
	"fmt"
	"io/fs"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Encode returns birth, modification, change and access fields in on-disk order.
// APFS uses signed Unix nanoseconds carried in uint64 slots. HFS uses unsigned
// seconds since 1904; subsecond precision is truncated by that format. The clamp
// applies only to modification time, not independently supplied metadata times.
func Encode(t hostdata.FileTimes, limit time.Time, clamp, hfs bool) ([4]uint64, error) {
	values := [4]time.Time{t.Birth, t.Modify, t.Change, t.Access}
	if clamp && values[1].After(limit) {
		values[1] = limit
	}
	var result [4]uint64
	for i, value := range values {
		if hfs {
			seconds := value.Unix()
			if seconds < -2082844800 || seconds > 2212122495 {
				return [4]uint64{}, fmt.Errorf("inode timestamp %d outside HFS range: %w", i, fs.ErrInvalid)
			}
			result[i] = uint64(seconds + 2082844800)
		} else {
			ns := value.UnixNano()
			if !time.Unix(0, ns).Equal(value) {
				return [4]uint64{}, fmt.Errorf("inode timestamp %d outside signed nanosecond range: %w", i, fs.ErrInvalid)
			}
			result[i] = uint64(ns)
		}
	}
	return result, nil
}
