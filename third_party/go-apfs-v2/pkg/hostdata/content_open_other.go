//go:build !darwin && !linux && !windows

package hostdata

import (
	"errors"
	"os"
)

func openContentAt(*os.File, string) (*os.File, error) {
	return nil, errors.ErrUnsupported
}
