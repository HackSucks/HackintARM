package hostdata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"
)

// Attribute-file resource forks have independent vnodes on FAT. Copy through
// held positional xattrs, as copyfile_rsrc does, rather than imposing the native
// APFS named-stream inode contract. AppleDouble lengths fit that 32-bit API.
func copyReplacementFilesystemMetadataContext(ctx context.Context, source, target *os.File) (result error) {
	view, err := FilesystemMetadataForFile(ctx, source)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, view.Close()) }()
	return copyReplacementFilesystemMetadataUsing(ctx, replacementFilesystemCopyOps{
		list:  func() ([]string, error) { return view.List(ctx, MaxXattrListSize) },
		read:  func(name string, limit int) ([]byte, bool, error) { return ReadXattr(source, name, limit) },
		write: func(name string, value []byte) error { return SetXattr(target, name, value) },
		fork: func() error {
			value, present, err := view.OpenValue(ctx, ResourceForkName)
			if err != nil {
				return err
			}
			if !present {
				return ErrXattrChanged
			}
			return errors.Join(copyReplacementFilesystemFork(ctx, value, target), value.Close())
		},
	})
}

type replacementFilesystemCopyOps struct {
	list  func() ([]string, error)
	read  func(string, int) ([]byte, bool, error)
	write func(string, []byte) error
	fork  func() error
}

func copyReplacementFilesystemMetadataUsing(ctx context.Context, ops replacementFilesystemCopyOps) (result error) {
	names, err := ops.list()
	if err != nil {
		return err
	}
	remaining := MaxXattrReadSize
	for _, name := range names {
		if err = ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		if name == ResourceForkName {
			// copyfile continues later attributes after a fork failure while
			// retaining the failure. Failed private stages are never published.
			result = errors.Join(result, ops.fork())
			continue
		}
		value, present, e := ops.read(name, remaining)
		if e != nil {
			return errors.Join(result, e)
		}
		if !present {
			return errors.Join(result, ErrXattrChanged)
		}
		remaining -= len(value)
		if e = ops.write(name, value); e != nil {
			return errors.Join(result, e)
		}
	}
	return errors.Join(result, ctx.Err())
}

func copyReplacementFilesystemFork(ctx context.Context, value *MetadataValue, target *os.File) error {
	return copyReplacementFilesystemForkUsing(ctx, value, func(data []byte, position uint32) error {
		name := []byte(ResourceForkName + "\x00")
		err := withXattrDescriptor(target, func(fd int) error {
			_, e := darwinabi.Fsetxattr(int32(fd), &name[0], unsafe.SliceData(data), uintptr(len(data)), position, 0)
			return e
		})
		runtime.KeepAlive(name)
		runtime.KeepAlive(data)
		return err
	})
}

func copyReplacementFilesystemForkUsing(ctx context.Context, value interface {
	io.ReaderAt
	Size() int64
}, write func([]byte, uint32) error) error {
	size := value.Size()
	if size < 0 || uint64(size) > 1<<32-1 {
		return fmt.Errorf("replacement resource fork: %w", os.ErrInvalid)
	}
	buffer := make([]byte, 64<<10)
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		data := buffer[:min(int64(len(buffer)), size-offset)]
		n, err := value.ReadAt(data, offset)
		if n != len(data) {
			return errors.Join(io.ErrUnexpectedEOF, err)
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = write(data, uint32(offset)); err != nil {
			return err
		}
		offset += int64(len(data))
	}
	return ctx.Err()
}
