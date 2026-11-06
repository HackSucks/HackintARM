//go:build !linux

package hostdata

import (
	"context"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func captureXattrValuesBound(ctx context.Context, _ *os.Root, _ string, file *os.File, limits XattrCaptureLimits) (map[string]appledouble.Value, error) {
	return CaptureXattrValues(ctx, file, limits)
}
