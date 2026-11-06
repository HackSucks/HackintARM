package hostdata

import "os"

// SetXattr assigns one native extended attribute through a caller-owned held
// descriptor. It creates or updates the attribute with ordinary native options;
// it does not reopen File.Name, close file, or change the file position. A held
// symlink refers to the link; an already-followed descriptor refers to its target.
// Windows reopens the held object for synchronous FILE_WRITE_EA access, checking
// the current DACL without requesting read access or backup privileges.
//
// Nil and empty values both request a zero-length assignment. The filesystem
// controls normalization, visibility, limits and side effects: Windows deletes
// empty EAs, Darwin ordinary attributes can be present-empty, zero FinderInfo
// becomes invisible, and writing a resource fork at offset zero need not truncate
// an existing fork. Success means the native call succeeded, not that a subsequent
// read must equal value. Use RemoveXattr for an explicit removal request.
//
// Errors retain their native causes; unsupported operations also match
// ErrXattrUnsupported. Windows applies its documented name restrictions and
// rejects values over the 65535-byte EA wire limit with ErrXattrTooLarge before
// allocating a record. The native filesystem may impose smaller/aggregate limits.
// Unix forwards the supplied buffer without an artificial read-size limit.
//
// The caller must not mutate value until the call returns and must exclude other
// metadata mutation when stable readback matters. This is a single native write,
// without retries, readback, rollback, atomic multi-attribute updates or a foreign
// metadata carrier. It is independent of the best-effort SetXattrs API.
func SetXattr(file *os.File, name string, value []byte) error {
	return withXattrFile(file, name, func(fd int) error {
		return setVisibleXattrFD(fd, name, value)
	})
}
