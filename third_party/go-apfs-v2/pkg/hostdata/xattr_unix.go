//go:build darwin || linux

package hostdata

import (
	"sort"

	"golang.org/x/sys/unix"
)

// XattrsSupported reports whether this build can read extended attributes.
const XattrsSupported = true

// ListXattrs returns every extended attribute on the file at path, without
// following a symbolic link — a link's own attributes are not its target's.
//
// The standard library exposes none of this: syscall has Listxattr and Getxattr
// on Linux only, has neither on darwin, and has no L-prefixed variant anywhere.
// golang.org/x/sys/unix has all of them, is pure Go, and works with cgo
// disabled.
//
// On macOS the attributes holding a compressed file's content are included; see
// listXattrNames in xattr_darwin.go, which is the only reason this is split by
// platform at all.
//
// A file with no attributes returns an empty map, not an error. So does a file
// system that does not support attributes: that is an absence of data, not a
// failure to read it.
func ListXattrs(path string) (map[string][]byte, error) {
	names, err := listXattrNames(path)
	if err != nil {
		if isUnsupported(err) {
			return map[string][]byte{}, nil
		}
		return nil, err
	}

	attrs := make(map[string][]byte, len(names))
	for _, name := range names {
		value, err := getXattr(path, name)
		if err != nil {
			// An attribute that vanished between listing and reading, or that
			// this process may not see, is not a reason to fail the walk.
			continue
		}
		attrs[name] = value
	}
	return attrs, nil
}

// isUnsupported reports whether err means "this file system has no extended
// attributes" rather than a genuine failure.
func isUnsupported(err error) bool {
	return err == unix.ENOTSUP || err == unix.EOPNOTSUPP || err == unix.ENOSYS
}

// SetXattrs writes attrs onto the file at path, without following a symbolic
// link. It returns the number written and the names it could not write.
//
// Failures are collected rather than aborting: an attribute the kernel reserves
// to itself (com.apple.provenance, say) or one the destination file system will
// not take should not stop the rest from being restored.
func SetXattrs(path string, attrs map[string][]byte) (written int, failed []string) {
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic order, so failures are reported the same way twice

	for _, name := range names {
		if err := unix.Lsetxattr(path, name, attrs[name], 0); err != nil {
			failed = append(failed, name)
			continue
		}
		written++
	}
	return written, failed
}
