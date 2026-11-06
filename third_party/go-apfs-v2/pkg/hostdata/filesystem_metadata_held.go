package hostdata

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// FilesystemMetadataForFile borrows the caller's held file; closing the view does
// not close it. Native storage uses that descriptor without pathname acquisition.
// FAT storage additionally resolves the held descriptor's current pathname and
// verifies the associated entry's identity. Keep the file open and exclude
// concurrent namespace changes. File.Name is only a label and is never used
// as association authority; an unresolvable or substituted path returns an error.
func FilesystemMetadataForFile(ctx context.Context, file *os.File) (*FilesystemMetadata, error) {
	return filesystemMetadataForFile(ctx, file, filesystemUsesAppleDouble)
}
func filesystemMetadataForFile(ctx context.Context, file *os.File, selectStorage func(*os.File) (bool, error)) (*FilesystemMetadata, error) {
	return filesystemMetadataForFileUsing(ctx, file, selectStorage, filesystemMetadataPath)
}
func filesystemMetadataForFileUsing(ctx context.Context, file *os.File, selectStorage func(*os.File) (bool, error), resolve func(context.Context, *os.File) (string, error)) (*FilesystemMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if file == nil {
		return nil, os.ErrInvalid
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	selected, err := selectStorage(file)
	if err != nil {
		return nil, err
	}
	v := &FilesystemMetadata{file: file, identity: info, sidecar: selected, borrowed: true, ops: defaultFilesystemMetadataOps()}
	if selected {
		path, err := resolve(ctx, file)
		if err != nil {
			return nil, err
		}
		parent, base := filepath.Split(path)
		if !filepath.IsAbs(path) || base == "" || base == "." || base == ".." {
			return nil, os.ErrInvalid
		}
		v.parent, err = os.OpenRoot(parent)
		if err != nil {
			return nil, err
		}
		v.name = base
		current, err := StatMetadata(v.parent, base)
		if err == nil && !os.SameFile(info, current) {
			err = ErrMetadataIdentity
		}
		if err != nil {
			return nil, errors.Join(err, v.Close())
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, errors.Join(err, v.Close())
	}
	return v, nil
}

// Size queries the visible value length without opening or allocating its data.
// This preserves native size-query authorization and supports large forks.
func (v *FilesystemMetadata) Size(ctx context.Context, name string) (size int64, present bool, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err = v.check(ctx); err != nil {
		return
	}
	if err = validXattrName(name); err != nil {
		return
	}
	if !v.sidecar {
		var n int
		n, present, err = v.ops.size(v.file, name)
		return int64(n), present, err
	}
	f, entries, err := v.appleDouble(ctx)
	if errors.Is(err, ErrXattrNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if f != nil {
		defer func() { err = errors.Join(err, f.Close()) }()
	}
	for _, entry := range entries {
		if entry.Name == name {
			return entry.Value.Size(), true, ctx.Err()
		}
	}
	return 0, false, ctx.Err()
}

// CaseInsensitiveNames describes native Windows EA matching. AppleDouble names
// remain case-sensitive on every host, including Windows FAT volumes.
func (v *FilesystemMetadata) CaseInsensitiveNames() bool {
	return runtime.GOOS == "windows" && !v.sidecar
}

// UsesAppleDouble reports whether the view resolves foreign FAT attribute
// storage itself. Darwin returns false because its filesystem handles that
// dispatch natively. This is an observation of storage, never a caller setting.
func (v *FilesystemMetadata) UsesAppleDouble() bool { return v.sidecar }
