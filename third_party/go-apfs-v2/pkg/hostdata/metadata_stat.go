package hostdata

import (
	"os"
	"path/filepath"
)

// StatMetadata returns metadata for an entry itself, including a final symlink,
// within root. It does not request permission to read the entry's data or extended
// attributes. On Windows it requests READ_CONTROL and FILE_READ_ATTRIBUTES from
// a handle opened relative to a held, contained parent. Windows may also grant
// attribute visibility through directory-list permission on that parent.
// Intermediate links must remain inside root. The returned identity is a point
// in time observation; callers must bind any later mutation to a held descriptor.
func StatMetadata(root *os.Root, name string) (os.FileInfo, error) {
	if root == nil || !filepath.IsLocal(name) {
		return nil, os.ErrInvalid
	}
	return statMetadata(root, name)
}
