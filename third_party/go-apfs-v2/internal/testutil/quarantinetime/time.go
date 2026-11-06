// Package quarantinetime validates native-generated quarantine timestamps
// without changing their bytes or relaxing unrelated metadata comparisons.
package quarantinetime

import (
	"bytes"
	"fmt"
	"strconv"
	"time"
)

// Interval brackets the complete invocation, including exec and descriptor
// acquisition. Native sandbox labeling may happen before copyfile is called.
type Interval struct{ Start, End time.Time }

// Validate requires the exact raw prefix and suffix surrounding an eight-digit
// lowercase hexadecimal timestamp. The generated time must lie within the
// invocation at the wire's one-second precision. Equal observed values must
// still be validated separately. This is not valid for copied source timestamps.
func Validate(value, prefix, suffix []byte, interval Interval) error {
	if interval.Start.IsZero() || interval.End.IsZero() || interval.End.Before(interval.Start) || interval.Start.Unix() < 0 || interval.End.Unix() > int64(^uint32(0)) {
		return fmt.Errorf("invalid invocation interval %s to %s", interval.Start, interval.End)
	}
	if len(value) != len(prefix)+8+len(suffix) || !bytes.HasPrefix(value, prefix) || !bytes.HasSuffix(value, suffix) {
		return fmt.Errorf("generated quarantine framing or non-time bytes differ: %x", value)
	}
	raw := string(value[len(prefix) : len(prefix)+8])
	stamp, err := strconv.ParseUint(raw, 16, 32)
	if err != nil || fmt.Sprintf("%08x", stamp) != raw {
		return fmt.Errorf("noncanonical generated quarantine timestamp %q", raw)
	}
	if int64(stamp) < interval.Start.Unix() || int64(stamp) > interval.End.Unix() {
		return fmt.Errorf("generated quarantine time %d outside invocation seconds [%d,%d]", stamp, interval.Start.Unix(), interval.End.Unix())
	}
	return nil
}
