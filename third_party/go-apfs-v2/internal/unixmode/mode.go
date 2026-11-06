// Package unixmode converts Go permission bits for portable image writers.
package unixmode

import "io/fs"

// Permissions returns the twelve Unix permission bits. Go's special bits live
// above the low nine permission bits and must be translated explicitly. When
// explicit is false, missing low permissions select fallback; special bits are
// always retained. File type selection belongs to the writer.
func Permissions(mode fs.FileMode, fallback uint16, explicit bool) uint16 {
	permissions := uint16(mode.Perm())
	if permissions == 0 && !explicit {
		permissions = fallback
	}
	for _, bit := range []struct {
		goBit   fs.FileMode
		unixBit uint16
	}{{fs.ModeSetuid, 04000}, {fs.ModeSetgid, 02000}, {fs.ModeSticky, 01000}} {
		if mode&bit.goBit != 0 {
			permissions |= bit.unixBit
		}
	}
	return permissions
}

// FilePermissions converts the twelve Unix permission bits to Go's layout.
// File type and unrelated inode flags are deliberately excluded.
func FilePermissions(mode uint16) fs.FileMode {
	permissions := fs.FileMode(mode & 0777)
	if mode&04000 != 0 {
		permissions |= fs.ModeSetuid
	}
	if mode&02000 != 0 {
		permissions |= fs.ModeSetgid
	}
	if mode&01000 != 0 {
		permissions |= fs.ModeSticky
	}
	return permissions
}
