package apfs

import "io/fs"

// BSDFlags reads the inode flag word without following the final symlink or
// reading payloads/xattrs. Hard links resolve to their common inode. Names use
// fs.ValidPath, including "." for the root; keep the image immutable.
func (v *Volume) BSDFlags(name string) (uint32, error) {
	if v == nil {
		return 0, &fs.PathError{Op: "bsdflags", Path: name, Err: fs.ErrInvalid}
	}
	entry, err := v.entryByFSName("bsdflags", name)
	if err != nil {
		return 0, err
	}
	return entry.Inode.BSDFlags, nil
}
