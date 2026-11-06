package hostdata

import (
	"context"
	"os"
)

func filesystemMetadataPath(ctx context.Context, file *os.File) (string, error) {
	return replacementFinalPath(ctx, file)
}
