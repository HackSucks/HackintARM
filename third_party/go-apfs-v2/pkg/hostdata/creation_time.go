package hostdata

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"
)

// ErrCreationTimeUnsupported identifies hosts without a supported creation-time
// setter. No modification-time or extended-attribute substitute is written.
var ErrCreationTimeUnsupported = errors.New("creation time is unsupported on this host")

// SetCreationTime sets the creation time of an already-open regular file,
// directory or symlink on
// Darwin (nanoseconds) or Windows (100-nanosecond precision). Windows refuses
// unrepresentable times instead of rounding. Other hosts return ErrCreationTimeUnsupported.
// It leaves contents, access/modification times, ownership, mode, ACLs and xattrs
// unchanged. The inode is updated, so all hard-link names observe the new time.
//
// The caller owns file and must keep it open and avoid concurrent metadata
// changes. The operation uses the held descriptor, never the file's original
// pathname. It does not close, sync or replace the file, or use a helper process.
func SetCreationTime(file *os.File, when time.Time) error {
	if file == nil {
		return os.ErrInvalid
	}
	defer runtime.KeepAlive(file)
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("set creation time: %w: require a regular file, directory or held symlink", os.ErrInvalid)
	}
	return setCreationTime(file, when)
}
