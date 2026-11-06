// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"encoding/binary"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

// Offsets within an apfs_obj_phys header.
const (
	objOffCksum   = 0
	objOffOID     = 8
	objOffXID     = 16
	objOffType    = 24
	objOffSubtype = 28
)

// setObjectHeader stamps the object header (oid/xid/type/subtype) onto block and
// then seals it with the Fletcher-64 checksum every APFS object carries. The
// checksum covers all bytes after the 8-byte checksum field, so every other
// field must already be written before this is called.
//
// block is the full object buffer; size is the object size in bytes (the block
// size for single-block objects, or the total size for the space manager).
func setObjectHeader(block []byte, size int, oid uint64, typ, subtype uint32) {
	setObjectHeaderXID(block, size, oid, typ, subtype, formatXID)
}

// setObjectHeaderXID is setObjectHeader with an explicit transaction id. Most
// objects are stamped at formatXID (the base state); the live volume and container
// superblocks carry the higher live xid when the volume has snapshots.
func setObjectHeaderXID(block []byte, size int, oid uint64, typ, subtype uint32, xid uint64) {
	binary.LittleEndian.PutUint64(block[objOffOID:], oid)
	binary.LittleEndian.PutUint64(block[objOffXID:], xid)
	binary.LittleEndian.PutUint32(block[objOffType:], typ)
	binary.LittleEndian.PutUint32(block[objOffSubtype:], subtype)

	// Checksum spans everything after the checksum field itself. The Fletcher-64
	// routine is shared with the MIT reader in pkg/apfs.
	cksum, err := apfs.CalculateFletcher64(block[objOffCksum+8:size], 0)
	if err != nil {
		// The only error paths are a nil buffer or a non-multiple-of-4 length;
		// neither can happen here because object sizes are block-size multiples.
		panic("apfswrite: fletcher64: " + err.Error())
	}
	binary.LittleEndian.PutUint64(block[objOffCksum:], cksum)
}
