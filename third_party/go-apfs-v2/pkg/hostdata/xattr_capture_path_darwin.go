package hostdata

import "context"

func captureXattrsPath(ctx context.Context, path string, limits XattrCaptureLimits) (map[string][]byte, error) {
	return captureXattrs(ctx, limits, func() ([]string, error) {
		return readXattrNames(func(b []byte) (int, error) { return darwinListXattrPath(path, b, xattrCompressionFlags) }, limits.NameBytes)
	}, func(name string, b []byte) (int, error) {
		return darwinGetXattrPath(path, name, b, xattrCompressionFlags)
	})
}
