package hfsplus

import (
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/internal/bsdflags"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

var _ hostdata.ImageMetadataFS = (*Volume)(nil)

// Metadata captures resolved catalog ownership, Unix mode, native flag view,
// timestamps and identity without reading attributes or data. Names follow
// fs.ValidPath; "." selects the root and symlinks are not followed. Keep the image
// immutable. HFS timestamps retain raw whole-second values since 1904.
func (v *Volume) Metadata(name string) (hostdata.ImageMetadata, error) {
	if v == nil || v.root == nil {
		return hostdata.ImageMetadata{}, &fs.PathError{Op: "metadata", Path: name, Err: fs.ErrInvalid}
	}
	e, err := v.entryByFSName("metadata", name)
	if err != nil {
		return hostdata.ImageMetadata{}, err
	}
	var b BSDInfo
	var id CatalogNodeID
	var times [4]hfsTime
	var finder uint16
	var locked bool
	if e.isDir {
		if e.folder == nil {
			return hostdata.ImageMetadata{}, &fs.PathError{Op: "metadata", Path: name, Err: fs.ErrInvalid}
		}
		f := e.folder
		b, id, finder = f.BSDInfo, f.FolderID, f.UserInfo.FinderFlags
		times = [4]hfsTime{f.CreateDate, f.ContentModDate, f.AttributeModDate, f.AccessDate}
	} else {
		if e.file == nil {
			return hostdata.ImageMetadata{}, &fs.PathError{Op: "metadata", Path: name, Err: fs.ErrInvalid}
		}
		f := e.file
		b, id, finder = f.BSDInfo, f.FileID, f.UserInfo.FinderFlags
		times = [4]hfsTime{f.CreateDate, f.ContentModDate, f.AttributeModDate, f.AccessDate}
		locked = f.Flags&HFSFileLockedMask != 0
	}
	return hostdata.ImageMetadata{UID: b.OwnerID, GID: b.GroupID, Mode: uint32(b.FileMode), BSDFlags: bsdflags.HFS(b.OwnerFlags, b.AdminFlags, b.FileMode, e.isDir, locked, finder), LinkID: uint64(id), Times: &hostdata.FileTimes{Birth: times[0].Time(), Modify: times[1].Time(), Change: times[2].Time(), Access: times[3].Time()}}, nil
}
