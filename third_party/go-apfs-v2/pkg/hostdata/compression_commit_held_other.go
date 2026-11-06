//go:build !darwin

package hostdata

import (
	"errors"
	"os"
)

func newHeldCompressionCommit(*os.File) (CompressionCommitBackend, error) {
	return nil, errors.ErrUnsupported
}

func newHeldCompressionInstallation(*os.File) (CompressionInstallationBackend, error) {
	return nil, errors.ErrUnsupported
}
