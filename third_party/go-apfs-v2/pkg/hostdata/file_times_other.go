//go:build !darwin && !linux && !windows

package hostdata

import (
	"os"
	"time"
)

func setFileTimes(_ *os.File, _, _ time.Time) error { return ErrFileTimesUnsupported }
