package hostdata

import (
	"context"
	"errors"
	"os"
)

// FilesystemUsesXattrFiles reports whether the held object's filesystem stores
// macOS attributes in companion files. Darwin queries the volume's native xattr
// capability; Linux and Windows use the qualified FAT/exFAT storage selection.
// Unlike FilesystemMetadata.UsesAppleDouble, this describes the storage even
// when Darwin's kernel handles the companion files. It neither closes file nor
// determines whether any particular neighboring file is an attribute carrier.
func FilesystemUsesXattrFiles(ctx context.Context, file *os.File) (bool, error) {
	return filesystemXattrStorageUsing(ctx, file, filesystemXattrStorage)
}

func filesystemXattrStorageUsing(ctx context.Context, file *os.File, query func(*os.File) (bool, error)) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	value, err := query(file)
	if err = errors.Join(err, ctx.Err()); err != nil {
		return false, err
	}
	return value, nil
}
