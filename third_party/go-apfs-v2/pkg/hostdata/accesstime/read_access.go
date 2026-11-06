package accesstime

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

// ErrReadAccessUnsupported identifies hosts without mapped-read access recording.
var ErrReadAccessUnsupported = errors.New("read-access recording is unsupported on this host")

// RecordReadAccess requests the filesystem's mapped-read access-time update for
// an open regular file on Darwin. It requires a readable descriptor, not metadata
// write permission. Other hosts return ErrReadAccessUnsupported.
//
// The operation creates and discards a bounded read-only private mapping without
// accessing mapped bytes. It does not change contents, file position, other
// timestamps, ownership, permissions, ACLs or xattrs. The filesystem controls the
// resulting access time; hard-link names observe the same inode update.
//
// The caller owns file and must keep it open through the call. No pathname is
// resolved, and no mapping remains after a successful return.
func RecordReadAccess(file *os.File) error {
	if file == nil {
		return os.ErrInvalid
	}
	defer runtime.KeepAlive(file)
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("record read access: %w: require a regular file", os.ErrInvalid)
	}
	return recordReadAccess(file)
}
