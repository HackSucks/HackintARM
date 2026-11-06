package hfsplus

import (
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/internal/bsdflags"
)

// BSDFlags returns the native HFS catalog flag view, resolving hard links but
// not the final symlink. Finder invisibility contributes UF_HIDDEN; file locked
// state normalizes immutable flags as native getbsdattr does. No attributes or
// payloads are loaded. Names use fs.ValidPath and "." selects the root.
func (v *Volume) BSDFlags(name string) (uint32, error) {
	if v == nil || v.root == nil {
		return 0, &fs.PathError{Op: "bsdflags", Path: name, Err: fs.ErrInvalid}
	}
	e, err := v.entryByFSName("bsdflags", name)
	if err != nil {
		return 0, err
	}
	if e.isDir {
		b := e.folder.BSDInfo
		return bsdflags.HFS(b.OwnerFlags, b.AdminFlags, b.FileMode, true, false, e.folder.UserInfo.FinderFlags), nil
	}
	b := e.file.BSDInfo
	return bsdflags.HFS(b.OwnerFlags, b.AdminFlags, b.FileMode, false, e.file.Flags&HFSFileLockedMask != 0, e.file.UserInfo.FinderFlags), nil
}
