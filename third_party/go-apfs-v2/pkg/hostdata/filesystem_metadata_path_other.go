//go:build !darwin && !linux && !windows

package hostdata

import (
	"context"
	"os"
)

func filesystemMetadataPath(context.Context, *os.File) (string, error) {
	return "", ErrXattrUnsupported
}
