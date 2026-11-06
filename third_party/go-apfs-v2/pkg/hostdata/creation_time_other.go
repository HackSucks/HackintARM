//go:build !darwin && !windows

package hostdata

import (
	"os"
	"time"
)

func setCreationTime(_ *os.File, _ time.Time) error {
	return ErrCreationTimeUnsupported
}
