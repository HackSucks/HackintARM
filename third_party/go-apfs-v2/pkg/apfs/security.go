package apfs

import (
	"io"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Security captures native-statx-compatible security properties from an APFS
// image without consulting the host's accounts or permissions. Names follow
// fs.ValidPath; symlinks are not followed. Files, directories, roots and resolved
// hard links use their actual inode metadata. The image must remain immutable
// during capture. Only the security value is read, with a 3116-byte limit;
// unrelated resource forks and attribute streams are not read. Corrupt/empty
// security storage is distinguished from absence through Disposition. Image
// I/O and lookup failures remain errors, never absent-ACL success.
func (v *Volume) Security(name string) (out hostdata.ImageSecurity, err error) {
	defer func() {
		if err != nil {
			out = hostdata.ImageSecurity{}
			err = &fs.PathError{Op: "security", Path: name, Err: err}
		}
	}()
	if !fs.ValidPath(name) {
		return out, fs.ErrInvalid
	}
	imagePath := "/"
	if name != "." {
		imagePath += name
	}
	entry, err := v.FileEntryByPath(imagePath)
	if err != nil {
		return out, err
	}
	return entry.security()
}

func (fe *FileEntry) security() (hostdata.ImageSecurity, error) {
	inode := fe.Inode
	present, err := fe.HasExtendedAttributeByName(hostdata.SecurityName)
	if err != nil {
		return hostdata.ImageSecurity{}, err
	}
	var value []byte
	if present {
		attr, err := fe.ExtendedAttributeByName(hostdata.SecurityName)
		if err != nil {
			return hostdata.ImageSecurity{}, err
		}
		value, err = imageSecurityValue(attr)
		if err != nil {
			return hostdata.ImageSecurity{}, err
		}
	}
	return hostdata.DecodeImageSecurity(inode.OwnerIdentifier, inode.GroupIdentifier, inode.FileMode, value), nil
}

// imageSecurityValue bounds the allocation independently of the image reader
// and requires the declared value to be read in full.
func imageSecurityValue(attr *ExtendedAttribute) ([]byte, error) {
	size, err := attr.Size()
	if err != nil {
		return nil, err
	}
	if !hostdata.SecurityRecordSizeValid(size) {
		return []byte{}, nil
	}
	value := make([]byte, int(size))
	n, err := attr.ReadAt(value, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n != len(value) {
		return nil, io.ErrUnexpectedEOF
	}
	return value, nil
}
