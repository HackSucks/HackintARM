// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import "encoding/binary"

// fsTreeCursor tracks the free positions inside a B-tree leaf/index node while its
// records are laid out. An APFS node stores keys growing forward from the key
// area and values growing backward from the end of the value area; the cursor
// holds both frontiers plus the offset of the next table-of-contents entry.
type fsTreeCursor struct {
	b          *builder
	block      []byte
	tocOff     int // byte offset of the next kvloc entry
	keyArea    int // start of the key area
	keyOff     int // next free position in the key area
	valAreaEnd int // end of the value area
	valEnd     int // current end of the free value area
}

// setKeyHeader packs the oid and record type into a file-system tree key's leading
// obj_id_and_type field (type in the high bits, id in the low bits). keyOff
// points at the start of the key.
func setKeyHeader(block []byte, keyOff int, ino, typ uint64) {
	objIDAndType := (typ << objTypeShift) | ino
	binary.LittleEndian.PutUint64(block[keyOff:], objIDAndType)
}

// putKvloc writes an apfs_kvloc entry at c.tocOff.
func (c *fsTreeCursor) putKvloc(kOff, kLen, vOff, vLen uint16) {
	binary.LittleEndian.PutUint16(c.block[c.tocOff+0:], kOff)
	binary.LittleEndian.PutUint16(c.block[c.tocOff+2:], kLen)
	binary.LittleEndian.PutUint16(c.block[c.tocOff+4:], vOff)
	binary.LittleEndian.PutUint16(c.block[c.tocOff+6:], vLen)
}
