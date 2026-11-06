//go:build !darwin && !linux && !windows

package accesstime

import "os"

func copyAccessTime(_ *os.File, _ os.FileInfo) error {
	return ErrAccessTimeUnsupported
}
