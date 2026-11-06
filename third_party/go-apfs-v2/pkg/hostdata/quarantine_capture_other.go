//go:build !darwin

package hostdata

import (
	"context"
	"errors"
)

func captureNativeQuarantineProcess(context.Context) (*QuarantineProcessCapture, error) {
	return nil, errors.ErrUnsupported
}
