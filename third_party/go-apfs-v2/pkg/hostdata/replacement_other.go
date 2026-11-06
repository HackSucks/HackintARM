//go:build !darwin && !linux && !windows

package hostdata

import (
	"context"
	"os"
)

func prepareReplacementContext(ctx context.Context, _ *os.File, _ string, _ os.FileInfo) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, ErrUnsupportedReplacement
}

func restoreReplacementMetadataContext(ctx context.Context, _, _ *os.File, _ os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrUnsupportedReplacement
}
