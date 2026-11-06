package accesstime

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

// ErrAccessTimeUnsupported identifies hosts without access-time copying.
var ErrAccessTimeUnsupported = errors.New("access-time copying is unsupported on this host")

// CopyAccessTime copies the current access time between distinct open regular
// files on Darwin, Linux or Windows, preserving the source's native precision.
// Other hosts return ErrAccessTimeUnsupported. It does not record a read or change source metadata.
// Target contents, position, creation/modification times, ownership, mode, ACLs
// and xattrs are unchanged; its metadata-change time may advance. Hard links to
// the target observe the update. Metadata-write permission is required.
//
// Both files remain caller-owned and must stay open without concurrent metadata
// changes. The operation targets held descriptors even when names are replaced.
// It does not sync, close or replace either file, or invoke a helper process.
func CopyAccessTime(source, target *os.File) error {
	if source == nil || target == nil {
		return os.ErrInvalid
	}
	defer runtime.KeepAlive(source)
	defer runtime.KeepAlive(target)
	from, err := source.Stat()
	if err != nil {
		return err
	}
	to, err := target.Stat()
	if err != nil {
		return err
	}
	if !from.Mode().IsRegular() || !to.Mode().IsRegular() || os.SameFile(from, to) {
		return fmt.Errorf("copy access time: %w: require distinct regular files", os.ErrInvalid)
	}
	return copyAccessTime(target, from)
}
