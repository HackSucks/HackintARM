package hostdata

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// OpenResourceFork opens a Darwin regular file resource fork associated with its
// held descriptor. The returned descriptor has an independent position and is
// caller-owned. Writable opens create a missing fork but do not truncate it.
// The data file remains caller-owned; closing it does not close the fork.
//
// macOS 26/27 use descriptor-relative acquisition. macOS 15 resolves the held
// descriptor current path and verifies the opened inode before any writes.
// That older kernel route cannot reopen unlinked forks and is not an atomic
// namespace snapshot; callers must exclude unrelated namespace edits. Neither
// route uses a 32-bit xattr position for resource-fork data.
//
// Other native hosts and object kinds return errors.ErrUnsupported; their complete
// logical resource forks are preserved through image/AppleDouble/carrier Values.
// Native authorization still applies. Empty Darwin forks normalize to absence.
func OpenResourceFork(file *os.File, writable bool) (*os.File, error) {
	return OpenResourceForkContext(context.TODO(), file, writable)
}

// OpenResourceForkContext is OpenResourceFork with cancellation at acquisition
// checkpoints. A completed native open may create an empty fork; cancellation
// closes its descriptor but does not claim to undo that native side effect.
func OpenResourceForkContext(ctx context.Context, file *os.File, writable bool) (*os.File, error) {
	return openResourceForkContextUsing(ctx, file, writable, openNativeResourceForkContext)
}
func openResourceForkContextUsing(ctx context.Context, file *os.File, writable bool, open func(context.Context, int, bool) (*os.File, error)) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fork, err := openResourceForkUsing(file, writable, func(fd int, write bool) (*os.File, error) {
		return open(ctx, fd, write)
	})
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, errors.Join(err, fork.Close())
	}
	return fork, nil
}

func openResourceForkUsing(file *os.File, writable bool, open func(int, bool) (*os.File, error)) (*os.File, error) {
	if file == nil {
		return nil, fs.ErrInvalid
	}
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.ErrUnsupported
	}
	var fork *os.File
	err = withXattrDescriptor(file, func(fd int) error { var e error; fork, e = open(fd, writable); return e })
	if err != nil {
		return nil, err
	}
	after, err := fork.Stat()
	if err != nil {
		return nil, errors.Join(err, fork.Close())
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.Join(ErrMetadataIdentity, fork.Close())
	}
	return fork, nil
}

type resourceForkSink interface {
	io.Writer
	Truncate(int64) error
	Close() error
}

// ReplaceResourceFork replaces native fork contents using a bounded 64 KiB
// buffer and 64-bit offsets. It first opens and validates fork identity, then
// truncates. Failure/cancellation can leave a partial fork; no rollback or disk
// durability is promised. The source must remain immutable and open until return.
// The caller retains the complete logical value independently when projecting
// onto a native host whose fork operations are unavailable.
func ReplaceResourceFork(ctx context.Context, file *os.File, value appledouble.Value) (int64, error) {
	return replaceResourceForkUsing(ctx, value, func() (resourceForkSink, error) { return OpenResourceForkContext(ctx, file, true) })
}
func replaceResourceForkUsing(ctx context.Context, value appledouble.Value, open func() (resourceForkSink, error)) (written int64, err error) {
	if ctx == nil || value == nil || value.Size() < 0 {
		return 0, fs.ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	size := value.Size()
	fork, err := open()
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, fork.Close()) }()
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	if err = fork.Truncate(0); err != nil {
		return 0, err
	}
	buf := make([]byte, 64<<10)
	for written < size {
		if err = ctx.Err(); err != nil {
			return written, err
		}
		if value.Size() != size {
			return written, ErrXattrChanged
		}
		count := int(min(int64(len(buf)), size-written))
		n, e := value.ReadAt(buf[:count], written)
		if n != count {
			return written, errors.Join(io.ErrUnexpectedEOF, e)
		}
		if e != nil && !errors.Is(e, io.EOF) {
			return written, e
		}
		n, e = fork.Write(buf[:count])
		if n < 0 || n > count {
			return written, io.ErrShortWrite
		}
		written += int64(n)
		if e != nil {
			return written, e
		}
		if n != count {
			return written, io.ErrShortWrite
		}
	}
	return written, ctx.Err()
}
