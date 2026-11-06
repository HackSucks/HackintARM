package hostdata

import (
	"context"
	"fmt"
	"os"
)

// XattrCaptureLimits bounds a complete capture's native name list, individual
// values and aggregate value allocation. Zero permits only an empty result.
// Unlike ReadXattr, this explicit-budget API can capture values above 8 MiB.
type XattrCaptureLimits struct {
	NameBytes  int
	ValueBytes int
	TotalBytes int
}

// CaptureXattrsNoFollow captures the final path component's own metadata.
// Unlike CaptureXattrs, path resolution is not pinned across the complete
// operation on Unix. Callers must exclude rename and symlink substitution;
// intermediate symlinks are followed. Use held files for untrusted paths.
func CaptureXattrsNoFollow(ctx context.Context, path string, limits XattrCaptureLimits) (map[string][]byte, error) {
	if ctx == nil || limits.NameBytes < 0 || limits.NameBytes > MaxXattrListSize || limits.ValueBytes < 0 || limits.TotalBytes < 0 {
		return nil, os.ErrInvalid
	}
	values, err := captureXattrsPath(ctx, path, limits)
	return values, strictXattrError(err)
}

// CaptureXattrs reads a complete native namespace from a caller-held file.
// Darwin includes compression-hidden storage attributes; Linux and Windows use
// their native namespaces. Foreign Darwin metadata belongs in a separate carrier.
// Errors return no partial snapshot. Disappearance, observed size changes and
// exhausted budgets are errors, never evidence that metadata is absent. The
// caller must prevent concurrent mutation: same-size edits cannot be detected.
// File remains caller-owned and is pinned against Close for the entire capture.
func CaptureXattrs(ctx context.Context, file *os.File, limits XattrCaptureLimits) (map[string][]byte, error) {
	if ctx == nil || limits.NameBytes < 0 || limits.NameBytes > MaxXattrListSize || limits.ValueBytes < 0 || limits.TotalBytes < 0 {
		return nil, os.ErrInvalid
	}
	var values map[string][]byte
	err := withXattrDescriptor(file, func(fd int) error {
		var err error
		values, err = captureXattrs(ctx, limits,
			func() ([]string, error) { return listCaptureXattrFD(fd, limits.NameBytes) },
			func(name string, buf []byte) (int, error) { return getCaptureXattrFD(fd, name, buf) })
		return err
	})
	if err != nil {
		return nil, err
	}
	return values, nil
}

func captureXattrs(ctx context.Context, limits XattrCaptureLimits, list func() ([]string, error), get func(string, []byte) (int, error)) (map[string][]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	names, err := list()
	if err != nil {
		return nil, err
	}
	values := make(map[string][]byte, len(names))
	remaining := limits.TotalBytes
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value, present, err := readVisibleXattr(func(buf []byte) (int, error) { return get(name, buf) }, min(limits.ValueBytes, remaining))
		if err != nil {
			return nil, fmt.Errorf("capture xattr %q: %w", name, err)
		}
		if !present {
			return nil, fmt.Errorf("capture xattr %q: %w", name, ErrXattrChanged)
		}
		values[name] = value
		remaining -= len(value)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return values, nil
}
