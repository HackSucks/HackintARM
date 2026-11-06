package apfs

import (
	"io/fs"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// FileTimes reads four inode timestamps without following the final symlink or
// reading payloads/xattrs. Names use fs.ValidPath; the image must stay immutable.
// Signed nanosecond bit patterns are retained, including dates before 1970.
func (v *Volume) FileTimes(name string) (hostdata.FileTimes, error) {
	if v == nil {
		return hostdata.FileTimes{}, &fs.PathError{Op: "timestamps", Path: name, Err: fs.ErrInvalid}
	}
	entry, err := v.entryByFSName("timestamps", name)
	if err != nil {
		return hostdata.FileTimes{}, err
	}
	inode := entry.Inode
	return hostdata.FileTimes{
		Birth:  time.Unix(0, int64(inode.CreationTime)).UTC(),
		Modify: time.Unix(0, int64(inode.ModificationTime)).UTC(),
		Change: time.Unix(0, int64(inode.InodeChangeTime)).UTC(),
		Access: time.Unix(0, int64(inode.AccessTime)).UTC(),
	}, nil
}
