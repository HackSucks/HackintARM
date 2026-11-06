package hostdata

import (
	"context"

	"golang.org/x/sys/unix"
)

func captureXattrsPath(ctx context.Context, path string, limits XattrCaptureLimits) (map[string][]byte, error) {
	return captureXattrs(ctx, limits, func() ([]string, error) {
		return readXattrNames(func(b []byte) (int, error) { return unix.Llistxattr(path, b) }, limits.NameBytes)
	}, func(name string, b []byte) (int, error) { return unix.Lgetxattr(path, name, b) })
}
