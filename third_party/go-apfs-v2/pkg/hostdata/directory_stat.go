package hostdata

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

// ErrUnsupportedDirectoryStat identifies directory metadata outside the supported
// host profile. The operation never falls back to a pathname or helper process.
var ErrUnsupportedDirectoryStat = errors.New("unsupported directory stat metadata")

// CopyDirectoryStat copies stat metadata between distinct, already-open host
// directories. It never copies contents, extended attributes or ACL entries.
// Darwin and Linux copy owner/group, mode and access/modification times; Darwin
// also copies supported BSD flags. Linux requires kernel 5.8 or newer for
// descriptor-relative timestamp updates. Windows copies ordinary attributes and
// access/modification times, leaving the security descriptor unchanged.
//
// Darwin drops setuid/setgid on nosuid volumes and omits tracked/protected flags,
// like COPYFILE_STAT. Unsupported source or target flags fail before mutation.
// Creation time is not explicitly copied; Darwin may lower it when an earlier
// modification time is set. Existing destination ACL entries remain, although
// changing mode can update a Linux POSIX ACL's mask.
//
// Both descriptors remain caller-owned. The caller must keep them open and avoid
// concurrent metadata changes. Errors after mutation may leave partial results;
// there is no rollback, pathname lookup, directory creation or replacement.
func CopyDirectoryStat(source, target *os.File) error {
	if source == nil || target == nil {
		return os.ErrInvalid
	}
	// Platform wrappers consume raw handle values; keep their owning Files alive
	// until every descriptor-based operation has returned.
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
	if !from.IsDir() || !to.IsDir() || os.SameFile(from, to) {
		return fmt.Errorf("%w: require distinct directories", ErrUnsupportedDirectoryStat)
	}
	return copyDirectoryStat(source, target, from, to)
}
