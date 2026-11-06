package hostdata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// Clone failure is not generally permission to copy: authorization, storage and
// source errors must survive. The platform supplies its precise capability errors.
func prepareReplacementUsing(clone func() error, unavailable func(error) bool, open func(bool) (*os.File, error), metadata func(*os.File) error) (*os.File, error) {
	return prepareReplacementUsingContext(context.Background(), clone, unavailable, open, metadata)
}
func prepareReplacementUsingContext(ctx context.Context, clone func() error, unavailable func(error) bool, open func(bool) (*os.File, error), metadata func(*os.File) error) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := clone()
	if canceled := ctx.Err(); canceled != nil {
		return nil, errors.Join(err, canceled)
	}
	cloned := err == nil
	if err != nil && !unavailable(err) {
		return nil, err
	}
	target, err := open(cloned)
	if err != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	if err = ctx.Err(); err != nil {
		return nil, errors.Join(err, target.Close())
	}
	if !cloned {
		err = metadata(target)
	}
	err = errors.Join(err, ctx.Err())
	if err != nil {
		return nil, errors.Join(err, target.Close())
	}
	return target, nil
}

type replacementFork interface {
	io.ReaderAt
	Stat() (os.FileInfo, error)
	Close() error
}

type replacementCopyOps struct {
	compressed  bool
	list        func() ([]string, error)
	read        func(string, int) ([]byte, bool, error)
	write       func(string, []byte) error
	openFork    func() (replacementFork, error)
	replaceFork func(appledouble.Value) error
	birth       func() error
}

// Only ordinary xattrs share the existing allocation budget. Resource forks are
// streamed through held descriptors and never squeezed into an xattr buffer.
// Security is deliberately deferred to RestoreMetadata, after content writes.
func copyReplacementMetadataUsing(ops replacementCopyOps) error {
	return copyReplacementMetadataUsingContext(context.Background(), ops)
}
func copyReplacementMetadataUsingContext(ctx context.Context, ops replacementCopyOps) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ops = ops.withContext(ctx)
	compressionFork := false
	if ops.compressed {
		value, present, err := ops.read(DecmpfsName, decmpfs.MaxAttributeSize)
		if err != nil {
			return fmt.Errorf("replacement compression: %w", err)
		}
		if !present {
			return fmt.Errorf("replacement compression: %w", ErrXattrChanged)
		}
		compressionFork, err = decmpfs.UsesResourceFork(bytes.NewReader(value))
		if err != nil {
			return fmt.Errorf("replacement compression: %w", err)
		}
	}
	names, err := ops.list()
	if err != nil {
		return err
	}
	remaining := MaxXattrReadSize
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if ops.compressed && (name == DecmpfsName || (compressionFork && name == ResourceForkName)) {
			continue
		}
		if name == "com.apple.ResourceFork" {
			if err := copyReplacementForkContext(ctx, ops); err != nil {
				return fmt.Errorf("replacement resource fork: %w", err)
			}
			continue
		}
		value, present, err := ops.read(name, remaining)
		if err != nil {
			return fmt.Errorf("replacement attribute %q: %w", name, err)
		}
		if !present {
			return fmt.Errorf("replacement attribute %q: %w", name, ErrXattrChanged)
		}
		remaining -= len(value)
		if err := ops.write(name, value); err != nil {
			return fmt.Errorf("replacement attribute %q: %w", name, err)
		}
	}
	return replacementStep(ctx, ops.birth)
}

func copyReplacementFork(ops replacementCopyOps) error {
	return copyReplacementForkContext(context.Background(), ops)
}
func copyReplacementForkContext(ctx context.Context, ops replacementCopyOps) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	ops = ops.withContext(ctx)
	fork, err := ops.openFork()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, fork.Close()) }()
	info, err := replacementValue(ctx, fork.Stat)
	if err != nil {
		return err
	}
	return ops.replaceFork(io.NewSectionReader(fork, 0, info.Size()))
}

func (ops replacementCopyOps) withContext(ctx context.Context) replacementCopyOps {
	return replacementCopyOps{
		compressed: ops.compressed,
		list:       func() ([]string, error) { return replacementValue(ctx, ops.list) },
		read: func(name string, limit int) ([]byte, bool, error) {
			if err := ctx.Err(); err != nil {
				return nil, false, err
			}
			value, present, err := ops.read(name, limit)
			return value, present, errors.Join(err, ctx.Err())
		},
		write: func(name string, value []byte) error {
			return replacementStep(ctx, func() error { return ops.write(name, value) })
		},
		openFork: func() (replacementFork, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			fork, err := ops.openFork()
			err = errors.Join(err, ctx.Err())
			if err != nil && fork != nil {
				err = errors.Join(err, fork.Close())
				fork = nil
			}
			return fork, err
		},
		replaceFork: func(value appledouble.Value) error {
			return replacementStep(ctx, func() error { return ops.replaceFork(value) })
		},
		birth: func() error { return replacementStep(ctx, ops.birth) },
	}
}
