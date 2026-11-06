//go:build !darwin && !linux && !windows

package hostdata

import "os"

func copyDirectoryStat(_, _ *os.File, _, _ os.FileInfo) error {
	return ErrUnsupportedDirectoryStat
}
