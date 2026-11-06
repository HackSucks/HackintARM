//go:build !darwin

package hostdata

import (
	"context"
	"errors"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func captureQuarantineFile(context.Context, *os.File, appledouble.QuarantineProfile) (*appledouble.Quarantine, error) {
	return nil, errors.ErrUnsupported
}
func applyQuarantineFile(context.Context, *os.File, *appledouble.Quarantine, QuarantineProcessCapture) error {
	return errors.ErrUnsupported
}
