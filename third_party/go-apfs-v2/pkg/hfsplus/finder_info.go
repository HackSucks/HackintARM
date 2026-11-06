package hfsplus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

const finderInfoName = "com.apple.FinderInfo"

// visibleFinderInfo follows hfs_zero_hidden_fields and hfs_vnop_getxattr:
// private document/date/generation words and symlink type/creator are hidden.
func visibleFinderInfo(raw [32]byte, symlink bool) []byte {
	clear(raw[16:24])
	clear(raw[28:32])
	if symlink {
		clear(raw[:8])
	}
	if raw == [32]byte{} {
		return nil
	}
	return raw[:]
}

func catalogFinderInfo(e *entry) []byte {
	var raw [32]byte
	if e.isDir {
		copy(raw[:16], marshalBE(&e.folder.UserInfo))
		copy(raw[16:], marshalBE(&e.folder.FinderInfo))
	} else {
		copy(raw[:16], marshalBE(&e.file.UserInfo))
		copy(raw[16:], marshalBE(&e.file.FinderInfo))
	}
	return visibleFinderInfo(raw, !e.isDir && e.file.BSDInfo.FileMode&0170000 == 0120000)
}

func addCatalogFinderInfo(attrs map[string][]byte, e *entry) error {
	visible := catalogFinderInfo(e)
	if stored, ok := attrs[finderInfoName]; ok && !bytes.Equal(stored, visible) {
		return fmt.Errorf("HFS catalog and noncanonical attribute-tree FinderInfo conflict")
	}
	delete(attrs, finderInfoName)
	if visible != nil {
		attrs[finderInfoName] = visible
	}
	return nil
}

func validateFinderInfo(e *Entry) error {
	b, ok := e.Xattrs[finderInfoName]
	if !ok {
		return nil
	}
	if len(b) != 32 {
		return fmt.Errorf("hfsplus: FinderInfo requires exactly 32 bytes")
	}
	if e.Mode&os.ModeSymlink == 0 && binary.BigEndian.Uint32(b[:4]) == HardLinkFileType {
		return fmt.Errorf("hfsplus: FinderInfo cannot set the reserved hard-link file type")
	}
	return nil
}

func nodeFinderInfo(n *fileNode) [32]byte {
	var raw [32]byte
	copy(raw[:], n.entry.Xattrs[finderInfoName])
	clear(raw[16:24])
	clear(raw[28:32])
	if n.isSymlink {
		clear(raw[:8])
	}
	// Explicit BSDFlags is the final stat selection, as in the existing writer.
	flags := binary.BigEndian.Uint16(raw[8:10]) &^ uint16(0x4000)
	if n.bsdFlags&0x8000 != 0 {
		flags |= 0x4000
	}
	binary.BigEndian.PutUint16(raw[8:10], flags)
	return raw
}

func setFolderFinderInfo(f *HFSPlusCatalogFolder, n *fileNode) {
	raw := nodeFinderInfo(n)
	// Fixed-size records cannot fail the binary decoder.
	_ = binary.Read(bytes.NewReader(raw[:16]), binary.BigEndian, &f.UserInfo)
	_ = binary.Read(bytes.NewReader(raw[16:]), binary.BigEndian, &f.FinderInfo)
}
func setFileFinderInfo(f *HFSPlusCatalogFile, n *fileNode) {
	raw := nodeFinderInfo(n)
	_ = binary.Read(bytes.NewReader(raw[:16]), binary.BigEndian, &f.UserInfo)
	_ = binary.Read(bytes.NewReader(raw[16:]), binary.BigEndian, &f.FinderInfo)
}
