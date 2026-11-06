package apfs

import (
	"io/fs"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

var _ hostdata.ImageMetadataFS = (*Volume)(nil)

// Metadata captures ownership, Unix mode, flags, four timestamps and resolved
// inode identity without reading data or attributes. Names follow fs.ValidPath;
// "." selects the root and symlinks are not followed. Keep the image immutable.
func (v *Volume) Metadata(name string) (hostdata.ImageMetadata, error) {
	if v == nil {
		return hostdata.ImageMetadata{}, &fs.PathError{Op: "metadata", Path: name, Err: fs.ErrInvalid}
	}
	entry, err := v.entryByFSName("metadata", name)
	if err != nil {
		return hostdata.ImageMetadata{}, err
	}
	inode := entry.Inode
	return hostdata.ImageMetadata{
		UID: inode.OwnerIdentifier, GID: inode.GroupIdentifier, Mode: uint32(inode.FileMode), BSDFlags: inode.BSDFlags, LinkID: inode.Identifier,
		Times: &hostdata.FileTimes{Birth: time.Unix(0, int64(inode.CreationTime)).UTC(), Modify: time.Unix(0, int64(inode.ModificationTime)).UTC(), Change: time.Unix(0, int64(inode.InodeChangeTime)).UTC(), Access: time.Unix(0, int64(inode.AccessTime)).UTC()},
	}, nil
}
