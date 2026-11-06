package hostdata

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrContentType identifies a non-regular object presented as file content.
var ErrContentType = errors.New("content reader requires a regular file")

// OpenContentFileRead opens a regular file beneath root for reading its data.
// Intermediate links must remain inside root; a final symlink or reparse point
// is never followed. The caller owns the returned file and must close it.
//
// Unlike metadata acquisition, this operation does not read the ACL or extended
// attributes and does not request Windows READ_CONTROL or FILE_READ_EA. It
// requests data and basic file-attribute access. Data denial remains an error.
// The held descriptor is the authoritative identity; there is no preliminary
// pathname stat that could require additional permissions. Callers must bind
// any later pathname mutation to that identity and impose their own read limit.
func OpenContentFileRead(root *os.Root, name string) (*os.File, error) {
	if root == nil || !filepath.IsLocal(name) {
		return nil, os.ErrInvalid
	}
	file, err := metadataParent(root, name, openContentAt)
	if err != nil {
		return nil, &os.PathError{Op: "opencontent", Path: name, Err: err}
	}
	return checkContentFile(file)
}

func checkContentFile(file *os.File) (*os.File, error) {
	info, err := file.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = ErrContentType
	}
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}
