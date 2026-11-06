package hfsplus

import (
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Security captures native-statx-compatible security properties from an HFS+ or
// HFSX image on any OS. Names follow fs.ValidPath; symlinks are not followed and
// hard links use the resolved catalog inode. The image must remain immutable.
// It reads only the bounded security value, not unrelated attribute forks or
// resource forks. Disposition distinguishes ignored storage from absence.
// This is metadata acquisition, not host authorization or a permissions check.
func (v *Volume) Security(name string) (out hostdata.ImageSecurity, err error) {
	defer func() {
		if err != nil {
			out = hostdata.ImageSecurity{}
			err = &fs.PathError{Op: "security", Path: name, Err: err}
		}
	}()
	if !fs.ValidPath(name) || v == nil || v.root == nil {
		return out, fs.ErrInvalid
	}
	entry, err := v.lookup(name)
	if err != nil {
		return out, err
	}
	var bsd BSDInfo
	var id CatalogNodeID
	if entry.isDir {
		if entry.folder == nil {
			return out, fs.ErrInvalid
		}
		bsd = entry.folder.BSDInfo
		id = entry.folder.FolderID
	} else {
		if entry.file == nil {
			return out, fs.ErrInvalid
		}
		bsd = entry.file.BSDInfo
		id = entry.file.FileID
	}
	if err = v.loadAttributes(); err != nil {
		return out, err
	}
	var value []byte
	if record := v.attributes[attrKey{fileID: id, name: hostdata.SecurityName}]; record != nil {
		size := uint64(len(record.inline))
		if record.inline == nil && !record.hasFork {
			return out, fs.ErrInvalid
		}
		if record.inline == nil {
			size = record.fork.LogicalSize
		}
		value = []byte{}
		if hostdata.SecurityRecordSizeValid(size) {
			value, err = v.attributeValue(id, hostdata.SecurityName)
			if err != nil {
				return out, err
			}
		}
	}
	return hostdata.DecodeImageSecurity(bsd.OwnerID, bsd.GroupID, bsd.FileMode, value), nil
}
