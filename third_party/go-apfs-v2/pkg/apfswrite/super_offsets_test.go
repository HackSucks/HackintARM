// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestVolumeSuperblockFieldOffsets pins the on-disk offsets of the fields this
// package writes late in apfs_superblock_t. encoding/binary.Write adds no
// padding, so the struct's declared field order and sizes are the layout — one
// wrong size silently shifts everything after it, and the reader would then be
// looking at the wrong bytes. These offsets come from the Apple File System
// Reference and must agree with pkg/apfs's parser.
func TestVolumeSuperblockFieldOffsets(t *testing.T) {
	role := uint16(0x00c0) // APFS_VOL_ROLE_UPDATE
	groupID := [16]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}

	vsb := &apfsSuperblock{}
	vsb.Magic = apfsMagic
	vsb.NextDocID = 0x11223344
	vsb.Role = role
	vsb.VolumeGroupID = groupID
	vsb.RootToXID = 0x5566778899aabbcc
	copy(vsb.Volname[:], "OFFSETS")

	block := make([]byte, 4096)
	marshalInto(block, vsb)

	cases := []struct {
		name   string
		offset int
		want   []byte
	}{
		{"apfs_magic", 32, []byte("APSB")},
		{"apfs_volname", 704, []byte("OFFSETS")},
		{"apfs_next_doc_id", 960, le32(0x11223344)},
		{"apfs_role", 964, le16(role)},
		{"apfs_root_to_xid", 968, le64(0x5566778899aabbcc)},
		{"apfs_volume_group_id", 1008, groupID[:]},
	}

	for _, tc := range cases {
		got := block[tc.offset : tc.offset+len(tc.want)]
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s at offset %d = %x, want %x", tc.name, tc.offset, got, tc.want)
		}
	}
}

func le16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}
