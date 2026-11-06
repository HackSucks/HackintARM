package hosttime

import (
	"fmt"
	"os"
	"time"
)

// Windows FILETIME uses 100ns ticks from 1601. Zero and all-ones are setter
// sentinels; signed LARGE_INTEGER time APIs also require the high bit clear.
func WindowsTicks(when time.Time) (uint64, error) {
	const epoch = int64(11644473600)
	const ticksPerSecond = int64(10000000)
	const max = int64(1<<63 - 1)
	sec, ns := when.Unix(), int64(when.Nanosecond())
	if ns%100 != 0 || sec < -epoch || sec > max/ticksPerSecond-epoch {
		return 0, fmt.Errorf("time cannot be represented as a Windows FILETIME: %w", os.ErrInvalid)
	}
	base := (sec + epoch) * ticksPerSecond
	if ns/100 > max-base {
		return 0, fmt.Errorf("time exceeds Windows FILETIME range: %w", os.ErrInvalid)
	}
	ticks := base + ns/100
	if ticks <= 0 {
		return 0, fmt.Errorf("time is a Windows FILETIME sentinel: %w", os.ErrInvalid)
	}
	return uint64(ticks), nil
}
