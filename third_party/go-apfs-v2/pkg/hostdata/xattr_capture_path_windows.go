package hostdata

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func captureXattrsPath(ctx context.Context, path string, limits XattrCaptureLimits) (map[string][]byte, error) {
	h, err := openXattrPath(path, windows.FILE_READ_EA)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	values, err := CaptureXattrs(ctx, f, limits)
	return values, errors.Join(err, f.Close())
}
