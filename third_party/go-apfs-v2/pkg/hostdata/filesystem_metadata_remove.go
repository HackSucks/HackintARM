package hostdata

import (
	"context"
	"errors"
	"os"
)

// Remove deletes a visible attribute from filesystem-selected storage. A missing
// value returns false, nil. Native operations retain the held descriptor's
// authorization; FAT mutations bind the associated carrier before writing it.
// The caller excludes concurrent namespace and metadata mutation. This operation
// is not transactional: an IO error after a write may leave partial changes.
func (v *FilesystemMetadata) Remove(ctx context.Context, name string) (removed bool, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err = v.check(ctx); err != nil {
		return
	}
	if err = validXattrName(name); err != nil {
		return
	}
	if !v.sidecar {
		return RemoveXattr(v.file, name)
	}
	source, _, err := v.appleDouble(ctx)
	if errors.Is(err, ErrXattrNotFound) {
		return false, nil
	}
	if err != nil || source == nil {
		return false, err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	info, err := source.Stat()
	if err != nil {
		return false, err
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	carrier := "._" + v.name
	writer, err := v.ops.writer(v.parent, carrier)
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, writer.Close()) }()
	current, err := writer.Stat()
	if err != nil {
		return false, err
	}
	if !os.SameFile(info, current) {
		return false, ErrMetadataIdentity
	}
	result, err := v.ops.remove(ctx, filesystemAttributeFile{writer, info.Size()}, name)
	if err != nil {
		return false, err
	}
	if result.Empty {
		if err = ctx.Err(); err != nil {
			return false, err
		}
		current, err = StatMetadata(v.parent, carrier)
		if err != nil {
			return false, err
		}
		if !os.SameFile(info, current) {
			return false, ErrMetadataIdentity
		}
		if err = v.ops.unlink(v.parent, carrier); err != nil {
			return false, err
		}
	}
	return result.Removed, nil
}

type filesystemAttributeFile struct {
	file *os.File
	size int64
}

func (f filesystemAttributeFile) Size() int64 { return f.size }
func (f filesystemAttributeFile) ReadAt(b []byte, offset int64) (int, error) {
	return f.file.ReadAt(b, offset)
}
func (f filesystemAttributeFile) WriteAt(b []byte, offset int64) (int, error) {
	return f.file.WriteAt(b, offset)
}
func (f filesystemAttributeFile) Truncate(size int64) error { return f.file.Truncate(size) }

func openFilesystemMetadataWriter(root *os.Root, name string) (*os.File, error) {
	return openMetadataChecked(root, name, func(root *os.Root, name string, _ os.FileInfo) (*os.File, error) {
		return root.OpenFile(name, os.O_RDWR, 0)
	})
}
