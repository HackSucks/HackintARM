package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// CaptureXattrValues captures ordinary attributes into owned bounded snapshots
// and borrows a Darwin regular file's resource fork without allocating its size.
// Limits bound names and owned bytes; native resource forks use 64-bit file IO.
// The caller keeps file open, excludes concurrent metadata edits and retains the
// context until all borrowed values have been consumed. No partial map is returned.
func CaptureXattrValues(ctx context.Context, file *os.File, limits XattrCaptureLimits) (map[string]appledouble.Value, error) {
	if ctx == nil || limits.NameBytes < 0 || limits.NameBytes > MaxXattrListSize || limits.ValueBytes < 0 || limits.TotalBytes < 0 {
		return nil, fs.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var values map[string]appledouble.Value
	err := withXattrDescriptor(file, func(fd int) error {
		var e error
		values, e = captureXattrValues(ctx, limits,
			func() ([]string, error) { return listCaptureXattrFD(fd, limits.NameBytes) },
			func(name string, p []byte) (int, error) { return getCaptureXattrFD(fd, name, p) },
			func() (appledouble.Value, error) {
				return borrowResourceFork(ctx, func() (*os.File, error) { return OpenResourceFork(file, false) })
			})
		return e
	})
	if err != nil {
		return nil, err
	}
	return values, nil
}

// CaptureXattrValuesAt binds capture to a held root without following the final
// link. Borrowed fork reads reopen through the root and check original identity;
// no descriptor is retained per entry. Keep root open and exclude concurrent
// changes, including same-size edits. Linux symlink namespaces are read through
// their held parent using procfs and no-follow operations with identity checks.
// Native errors remain explicit; they never become an absent carrier value.
func CaptureXattrValuesAt(ctx context.Context, root *os.Root, name string, limits XattrCaptureLimits) (values map[string]appledouble.Value, err error) {
	capture := func(ctx context.Context, file *os.File, limits XattrCaptureLimits) (map[string]appledouble.Value, error) {
		return captureXattrValuesBound(ctx, root, name, file, limits)
	}
	return captureXattrValuesAt(ctx, root, name, limits, xattrValueOps{OpenMetadataFileRead, capture, func(file *os.File) (*os.File, error) { return OpenResourceFork(file, false) }})
}

type xattrValueOps struct {
	open    func(*os.Root, string) (*os.File, error)
	capture func(context.Context, *os.File, XattrCaptureLimits) (map[string]appledouble.Value, error)
	fork    func(*os.File) (*os.File, error)
}

func captureXattrValuesAt(ctx context.Context, root *os.Root, name string, limits XattrCaptureLimits, ops xattrValueOps) (values map[string]appledouble.Value, err error) {
	file, err := ops.open(root, name)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, file.Close())
		if err != nil {
			values = nil
		}
	}()
	original, err := file.Stat()
	if err != nil {
		return nil, err
	}
	values, err = ops.capture(ctx, file, limits)
	if err != nil {
		return nil, err
	}
	if value, ok := values[ResourceForkName].(*resourceForkValue); ok {
		value.open = func() (*os.File, error) {
			data, e := ops.open(root, name)
			if e != nil {
				return nil, e
			}
			info, e := data.Stat()
			if e == nil && !os.SameFile(original, info) {
				e = ErrMetadataIdentity
			}
			var fork *os.File
			if e == nil {
				fork, e = ops.fork(data)
			}
			if closeErr := data.Close(); closeErr != nil {
				e = errors.Join(e, closeErr)
				if fork != nil {
					e = errors.Join(e, fork.Close())
					fork = nil
				}
			}
			return fork, e
		}
	}
	return values, nil
}

func captureXattrValues(ctx context.Context, limits XattrCaptureLimits, list func() ([]string, error), get func(string, []byte) (int, error), fork func() (appledouble.Value, error)) (map[string]appledouble.Value, error) {
	names, err := list()
	if err != nil {
		return nil, err
	}
	values := make(map[string]appledouble.Value, len(names))
	remaining := limits.TotalBytes
	for _, name := range names {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if _, exists := values[name]; exists {
			return nil, ErrXattrChanged
		}
		if name == ResourceForkName {
			value, e := fork()
			if e == nil {
				values[name] = value
				continue
			}
			if !errors.Is(e, errors.ErrUnsupported) {
				return nil, e
			}
		}
		value, present, e := readVisibleXattr(func(p []byte) (int, error) { return get(name, p) }, min(limits.ValueBytes, remaining))
		if e != nil {
			return nil, e
		}
		if !present {
			return nil, ErrXattrChanged
		}
		values[name] = bytes.NewReader(value)
		remaining -= len(value)
	}
	return values, ctx.Err()
}

type resourceForkValue struct {
	ctx  context.Context
	size int64
	open func() (*os.File, error)
}

func borrowResourceFork(ctx context.Context, open func() (*os.File, error)) (appledouble.Value, error) {
	fork, err := open()
	if err != nil {
		return nil, err
	}
	info, statErr := fork.Stat()
	err = errors.Join(statErr, fork.Close())
	if err != nil {
		return nil, err
	}
	if info.Size() < 0 {
		return nil, fs.ErrInvalid
	}
	return &resourceForkValue{ctx: ctx, size: info.Size(), open: open}, nil
}
func (v *resourceForkValue) Size() int64 { return v.size }
func (v *resourceForkValue) ReadAt(p []byte, off int64) (n int, err error) {
	if err = v.ctx.Err(); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	fork, err := v.open()
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, fork.Close()) }()
	info, err := fork.Stat()
	if err != nil {
		return 0, err
	}
	if info.Size() != v.size {
		return 0, ErrXattrChanged
	}
	return io.NewSectionReader(fork, 0, v.size).ReadAt(p, off)
}
