package hostdata

import (
	"context"
	"os"
)

func prepareReplacementAtContext(ctx context.Context, _ *os.File, stage *os.Root, _ os.FileInfo) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return stage.OpenFile("replacement", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
}

func restoreReplacementMetadataAtContext(ctx context.Context, source, target *os.File, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return restoreReplacementMetadataContext(ctx, source, target, info)
}
