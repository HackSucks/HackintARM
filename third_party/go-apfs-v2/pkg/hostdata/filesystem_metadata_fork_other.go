//go:build !darwin

package hostdata

import (
	"context"
	"os"
)

func nativeFilesystemResource(context.Context, *os.File) (*MetadataValue, error) { return nil, nil }
