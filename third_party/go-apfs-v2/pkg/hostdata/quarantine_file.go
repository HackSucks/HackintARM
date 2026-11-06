package hostdata

import (
	"context"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// CaptureQuarantineFile imports the native kernel's quarantine view of a held
// file using the selected qualified host profile. A nil model and nil error
// confirm absence. Errors, including invalid stored values, never imply absence.
// Linux/Windows use explicitly captured image/carrier attributes and the portable
// appledouble parser; this native acquisition operation is unsupported there.
func CaptureQuarantineFile(ctx context.Context, file *os.File, profile appledouble.QuarantineProfile) (*appledouble.Quarantine, error) {
	if ctx == nil || file == nil {
		return nil, os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return captureQuarantineFile(ctx, file, profile)
}

// ApplyQuarantineFile submits the original Go-serialized model to native Darwin
// quarantine I/O. Nil requests native label removal. process must describe this
// host's current captured context; it is checked again before mutation. The
// native kernel performs its own authorization and normalization. Do not pass
// PlanApplication's final value back through this native operation: the portable
// plan is for logical/image restoration and independent native comparison.
// The caller owns file and excludes concurrent process-label/metadata changes.
func ApplyQuarantineFile(ctx context.Context, file *os.File, source *appledouble.Quarantine, process QuarantineProcessCapture) error {
	if ctx == nil || file == nil {
		return os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := process.Process(); err != nil {
		return err
	}
	return applyQuarantineFile(ctx, file, source, process)
}
