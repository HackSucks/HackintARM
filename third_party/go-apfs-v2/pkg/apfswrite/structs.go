// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"bytes"
	"encoding/binary"
)

// These structs describe the APFS on-disk objects this package writes. Every
// field is fixed size and declared in on-disk order, so encoding/binary.Write
// (which adds no alignment padding) reproduces the exact little-endian layout
// the format requires. The leading object header (objPhys) is left zero here
// and filled in later by setObjectHeader, which also computes the checksum.

type objPhys struct {
	Cksum   uint64
	OID     uint64
	XID     uint64
	Type    uint32
	Subtype uint32
}

type prange struct {
	StartPaddr uint64
	BlockCount uint64
}

// nxSuperblock is the on-disk apfs_nx_superblock.
type nxSuperblock struct {
	O                          objPhys
	Magic                      uint32
	BlockSize                  uint32
	BlockCount                 uint64
	Features                   uint64
	ReadonlyCompatibleFeatures uint64
	IncompatibleFeatures       uint64
	UUID                       [16]byte
	NextOID                    uint64
	NextXID                    uint64
	XpDescBlocks               uint32
	XpDataBlocks               uint32
	XpDescBase                 uint64
	XpDataBase                 uint64
	XpDescNext                 uint32
	XpDataNext                 uint32
	XpDescIndex                uint32
	XpDescLen                  uint32
	XpDataIndex                uint32
	XpDataLen                  uint32
	SpacemanOID                uint64
	OmapOID                    uint64
	ReaperOID                  uint64
	TestType                   uint32
	MaxFileSystems             uint32
	FsOID                      [nxMaxFileSystems]uint64
	Counters                   [32]uint64
	BlockedOutPrange           prange
	EvictMappingTreeOID        uint64
	Flags                      uint64
	EfiJumpstart               uint64
	FusionUUID                 [16]byte
	Keylocker                  prange
	EphemeralInfo              [4]uint64
	TestOID                    uint64
	FusionMtOID                uint64
	FusionWbcOID               uint64
	FusionWbc                  prange
	NewestMountedVersion       uint64
	MkbLocker                  prange
}

// wrappedMetaCryptoState is the on-disk apfs_wrapped_meta_crypto_state.
type wrappedMetaCryptoState struct {
	MajorVersion    uint16
	MinorVersion    uint16
	Cpflags         uint32
	PersistentClass uint32
	KeyOSVersion    uint32
	KeyRevision     uint16
	Unused          uint16
}

// apfsModifiedBy is the on-disk apfs_modified_by.
type apfsModifiedBy struct {
	ID        [32]byte
	Timestamp uint64
	LastXID   uint64
}

// apfsSuperblock is the on-disk apfs_superblock (the volume superblock).
type apfsSuperblock struct {
	O                          objPhys
	Magic                      uint32
	FsIndex                    uint32
	Features                   uint64
	ReadonlyCompatibleFeatures uint64
	IncompatibleFeatures       uint64
	UnmountTime                uint64
	FsReserveBlockCount        uint64
	FsQuotaBlockCount          uint64
	FsAllocCount               uint64
	MetaCrypto                 wrappedMetaCryptoState
	RootTreeType               uint32
	ExtentrefTreeType          uint32
	SnapMetaTreeType           uint32
	OmapOID                    uint64
	RootTreeOID                uint64
	ExtentrefTreeOID           uint64
	SnapMetaTreeOID            uint64
	RevertToXID                uint64
	RevertToSblockOID          uint64
	NextObjID                  uint64
	NumFiles                   uint64
	NumDirectories             uint64
	NumSymlinks                uint64
	NumOtherFsobjects          uint64
	NumSnapshots               uint64
	TotalBlocksAlloced         uint64
	TotalBlocksFreed           uint64
	VolUUID                    [16]byte
	LastModTime                uint64
	FsFlags                    uint64
	FormattedBy                apfsModifiedBy
	ModifiedBy                 [8]apfsModifiedBy
	Volname                    [volnameLen]byte
	NextDocID                  uint32
	Role                       uint16
	Reserved                   uint16
	RootToXID                  uint64
	ErStateOID                 uint64
	CloneinfoIDEpoch           uint64
	CloneinfoXID               uint64
	SnapMetaExtOID             uint64
	VolumeGroupID              [16]byte
	IntegrityMetaOID           uint64
	FextTreeOID                uint64
	FextTreeType               uint32
	ReservedType               uint32
	ReservedOID                uint64
	DocIDIndexXID              uint64
	DocIDIndexFlags            uint32
	DocIDTreeType              uint32
	DocIDTreeOID               uint64
	PrevDocIDTreeOID           uint64
	DocIDFixupCursor           uint64
	SecRootTreeOID             uint64
	SecRootTreeType            uint32
}

// omapPhys is the on-disk apfs_omap_phys.
type omapPhys struct {
	O                objPhys
	Flags            uint32
	SnapCount        uint32
	TreeType         uint32
	SnapshotTreeType uint32
	TreeOID          uint64
	SnapshotTreeOID  uint64
	MostRecentSnap   uint64
	PendingRevertMin uint64
	PendingRevertMax uint64
}

// nxReaperPhys is the fixed portion of the on-disk apfs_nx_reaper_phys.
type nxReaperPhys struct {
	O               objPhys
	NextReapID      uint64
	CompletedID     uint64
	Head            uint64
	Tail            uint64
	Flags           uint32
	Rlcount         uint32
	Type            uint32
	Size            uint32
	FsOID           uint64
	OID             uint64
	XID             uint64
	NrleFlags       uint32
	StateBufferSize uint32
}

// marshalInto serializes s (little-endian, no padding) into the front of block.
func marshalInto(block []byte, s any) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, s); err != nil {
		panic("apfswrite: marshal: " + err.Error())
	}
	copy(block, buf.Bytes())
}
