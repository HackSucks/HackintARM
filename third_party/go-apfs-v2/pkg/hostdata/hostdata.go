// Package hostdata handles host filesystem metadata shared by image tools and
// other consumers: extended attributes, hard-link identity and BSD flags.
//
// The writers need these to report what a directory-to-volume write cannot
// carry across. ListXattrs/SetXattrs report best-effort extraction fidelity.
// PrepareReplacement instead requires preservation of its supported metadata
// and returns an error before the caller commits an unsupported replacement.
package hostdata

import "os"

// Attribute names that mean something more specific than "an extended
// attribute" and are worth reporting separately.
const (
	// ResourceForkName holds a file's resource fork — content, not metadata.
	ResourceForkName = "com.apple.ResourceFork"
	// DecmpfsName marks a transparently compressed file. Its content lives in
	// the resource fork or in the attribute itself.
	DecmpfsName = "com.apple.decmpfs"
	// SecurityName is where macOS keeps a file's ACL.
	SecurityName = "com.apple.system.Security"
	// PosixACLAccessName is the Linux equivalent.
	PosixACLAccessName = "system.posix_acl_access"
)

// IsACLName reports whether an attribute name holds an access control list.
func IsACLName(name string) bool {
	return name == SecurityName || name == PosixACLAccessName
}

// UFCompressed is the UF_COMPRESSED bit of a file's BSD flags: the content is
// held by DecmpfsName rather than by the data fork. macOS decides whether a
// file is compressed by this flag, not by the attribute, so a file with one and
// not the other reads as empty.
//
// It is defined here rather than taken from a platform package because it is
// wanted on every platform: the flags themselves only exist on macOS, but the
// code that decides what to do about them is shared.
const UFCompressed uint32 = 0x00000020

// LinkIdentity identifies the inode behind a directory entry, so two names for
// one file can be recognized as such. ok is false on platforms that do not
// expose it, in which case hard links are indistinguishable from copies.
type LinkIdentity struct {
	Device uint64
	Inode  uint64
	Links  uint64 // st_nlink; greater than 1 means the file has several names
}

// IsSpecial reports whether mode describes something the writers cannot model:
// a device node, FIFO or socket. os.ModeIrregular covers whatever else a
// platform may report that is neither a regular file, a directory nor a
// symbolic link.
func IsSpecial(mode os.FileMode) bool {
	return mode&(os.ModeDevice|os.ModeNamedPipe|os.ModeSocket|os.ModeIrregular) != 0
}
