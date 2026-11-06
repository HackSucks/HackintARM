package hostdata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// Linux O_PATH pins a symlink's identity but is not accepted by flistxattr.
// Resolve only its leaf through a held parent and use the no-follow xattr API.
func captureXattrValuesBound(ctx context.Context, root *os.Root, name string, file *os.File, limits XattrCaptureLimits) (values map[string]appledouble.Value, err error) {
	original, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if original.Mode()&os.ModeSymlink == 0 {
		return CaptureXattrValues(ctx, file, limits)
	}
	parent, err := root.Open(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, parent.Close())
		if err != nil {
			values = nil
		}
	}()
	return captureLinkXattrValues(ctx, parent, filepath.Base(name), original, limits, CaptureXattrsNoFollow)
}

func captureLinkXattrValues(ctx context.Context, parent *os.File, base string, original os.FileInfo, limits XattrCaptureLimits, capture func(context.Context, string, XattrCaptureLimits) (map[string][]byte, error)) (values map[string]appledouble.Value, err error) {
	err = withXattrDescriptor(parent, func(fd int) error {
		// procfs refers to the held directory even if its original path is renamed.
		// A missing/unusable procfs fails explicitly; no pathname fallback follows
		// the symlink target. Callers still exclude concurrent edits and name
		// substitution followed by replacement with the original entry.
		bound := fmt.Sprintf("/proc/self/fd/%d/%s", fd, base)
		check := func() error {
			current, e := os.Lstat(bound)
			if e != nil {
				return e
			}
			if !os.SameFile(original, current) || current.Mode()&os.ModeSymlink == 0 {
				return ErrMetadataIdentity
			}
			return nil
		}
		if e := check(); e != nil {
			return e
		}
		attrs, e := capture(ctx, bound, limits)
		if e != nil {
			return e
		}
		if e = check(); e != nil {
			return e
		}
		values = make(map[string]appledouble.Value, len(attrs))
		for name, data := range attrs {
			values[name] = bytes.NewReader(data)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return values, nil
}
