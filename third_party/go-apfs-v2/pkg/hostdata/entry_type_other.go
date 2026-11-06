//go:build !darwin && !linux && !windows

package hostdata

import (
	"errors"
	"os"
)

func readEntryType(*os.Root, string) (os.FileMode, error) { return 0, errors.ErrUnsupported }
