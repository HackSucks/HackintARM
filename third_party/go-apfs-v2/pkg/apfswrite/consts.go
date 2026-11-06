// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

// Package apfswrite builds APFS containers from scratch in pure Go. It writes a
// complete single-volume container — either empty (just the root directory and
// the standard special inodes) or populated with a directory tree of files,
// symbolic links and nested directories.
//
// The implementation writes the whole container as one static checkpoint
// (transaction id 1): every object is laid out in its final position up front,
// which sidesteps copy-on-write mutation entirely. All on-disk layouts are
// derived from the published APFS format (Apple's "Apple File System
// Reference"). apfsprogs/mkapfs was consulted as a reference for the format's
// behaviour, but this is an independent implementation, not a translation; it
// is MIT-licensed like the rest of the toolkit.
package apfswrite

// On-disk constants defined by the APFS format. The value names follow the
// format's own naming (nx_*, apfs_*, obj_*) so they read against the spec.

// Object identifier constants.
const (
	oidNXSuperblock  = 1
	oidReservedCount = 1024
)

// Object type masks and flags.
const (
	objStoragetypeMask = 0xc0000000 //nolint:unused // spec mask; storage types are set whole

	objVirtual   = 0x00000000
	objEphemeral = 0x80000000
	objPhysical  = 0x40000000
)

// Object types.
const (
	objectTypeNXSuperblock      = 0x00000001
	objectTypeBtree             = 0x00000002
	objectTypeBtreeNode         = 0x00000003
	objectTypeSpaceman          = 0x00000005
	objectTypeSpacemanCAB       = 0x00000006
	objectTypeSpacemanCIB       = 0x00000007
	objectTypeSpacemanBitmap    = 0x00000008
	objectTypeSpacemanFreeQueue = 0x00000009
	objectTypeOmap              = 0x0000000b
	objectTypeCheckpointMap     = 0x0000000c
	objectTypeFS                = 0x0000000d
	objectTypeFSTree            = 0x0000000e
	objectTypeBlockrefTree      = 0x0000000f
	objectTypeSnapMetaTree      = 0x00000010
	objectTypeNXReaper          = 0x00000011
	objectTypeOmapSnapshot      = 0x00000013
	objectTypeFusionMiddleTree  = 0x00000015
	objectTypeNXFusionWBC       = 0x00000016
	objectTypeInvalid           = 0x00000000
)

// formatXID is the transaction id stamped on every object. Because the container
// is written as a single static checkpoint, there is only ever one xid.
const formatXID = 1

// B-tree node flags.
const (
	btnodeRoot        = 0x0001
	btnodeLeaf        = 0x0002
	btnodeFixedKVSize = 0x0004
)

// B-tree location constant.
const btoffInvalid = 0xffff

// B-tree info flags.
const (
	btreeAllowGhosts  = 0x00000004
	btreeEphemeral    = 0x00000008
	btreePhysical     = 0x00000010
	btreeKVNonaligned = 0x00000040
)

// Object map flags.
const omapManuallyManaged = 0x00000001

// Inode numbers for special inodes. These are the same on every volume,
// including the system volume of a volume group; only the user inode numbers
// from minUserInoNum up move into the group's upper half. See inoBaseFor.
const (
	rootDirParent = 1
	rootDirInoNum = 2
	privDirInoNum = 3
	minUserInoNum = 16
)

// unifiedIDSpaceMark (UNIFIED_ID_SPACE_MARK) divides the single inode-number
// space a volume group shares between its two members: the data volume numbers
// below it, the system volume at or above it.
const unifiedIDSpaceMark = 0x0800000000000000

// File-system tree record types (APFS_TYPE_*).
const (
	typeSnapMetadata = 1
	typeExtent       = 2
	typeInode        = 3
	typeXattr        = 4
	typeSiblingLink  = 5
	typeDstreamID    = 6
	typeFileExtent   = 8
	typeDirRec       = 9
	typeSiblingMap   = 12
	typeSnapName     = 11
)

// Snapshot on-disk sizes.
const (
	sizeofSnapMetadataVal = 50 // extentref_oid(8)+sblock_oid(8)+create(8)+change(8)+inum(8)+extentref_type(4)+flags(4)+name_len(2)
	sizeofOmapSnapshot    = 16 // oms_flags(4)+oms_pad(4)+oms_oid(8)
)

// Extended-attribute value flags (j_xattr_val_t flags, XATTR_DATA_*).
const (
	xattrDataStream      = 0x0001
	xattrDataEmbedded    = 0x0002
	xattrFileSystemOwned = 0x0004
)

// Key header field shift.
const objTypeShift = 60

// Directory entry name/hash masks.
const drecLenMask = 0x000003ff

// Inode internal flag: no resource fork. fsck_apfs expects this to be set on
// the special/root directory inodes we create.
const (
	inodeHasSecurityEA = 0x00000040
	inodeHasFinderInfo = 0x00000100
	// inodeHasRsrcFork is unused while resource forks are refused: it becomes
	// required the moment they can be written as a data stream.
	inodeHasRsrcFork = 0x00004000 //nolint:unused // needed for stream-based resource forks
	inodeNoRsrcFork  = 0x00008000

	// inodeHasUncompressedSize says the uncompressed_size field carries the
	// decompressed length of a compressed file. Without it that field is
	// padding, and Apple's implementation ignored it entirely before macOS
	// 10.15.
	inodeHasUncompressedSize = 0x00040000 //nolint:unused // documents why uncompressed_size stays padding
)

// BSD file flags (chflags(2)), stored in j_inode_val's bsd_flags.
const (
	// inoBSDCompressed is UF_COMPRESSED: the file's content is held by
	// com.apple.decmpfs rather than by its data fork. It must agree with the
	// presence of that attribute.
	inoBSDCompressed = 0x00000020
)

// Extended field types for inodes.
const (
	inoExtTypeName    = 4
	inoExtTypeDstream = 8
)

// Extended field flags.
const (
	xfDoNotCopy   = 0x02
	xfSystemField = 0x20
)

// S_IFREG / S_IFLNK from <sys/stat.h>, used for file-type mode bits.
const (
	sIFREG = 0o100000
	sIFLNK = 0o120000
)

// Directory entry type (drec val flags & APFS_DREC_TYPE_MASK): the file-type
// nibble of the mode. DT_REG == S_IFREG >> 12, DT_DIR == S_IFDIR >> 12,
// DT_LNK == S_IFLNK >> 12.
const (
	dtReg = sIFREG >> 12
	dtDir = sIFDIR >> 12
	dtLnk = sIFLNK >> 12
)

// Physical-extent record kinds and the shift of the kind field within
// len_and_kind (PEXT_KIND_*, PEXT_KIND_SHIFT).
const (
	pextKindNew   = 1
	pextKindShift = 60
)

// Constant for extended fields.
const minDocID = 3

// Container constants.
const (
	nxMagic          = 0x4253584e
	nxBlockNum       = 0
	nxMaxFileSystems = 100

	nxEphMinBlockCount        = 8
	nxMaxFileSystemEphStructs = 4
	nxEphInfoVersion1         = 1

	// nxDefaultBlockSize is the only block size this writer emits. The minimum
	// and maximum are the format's, recorded because they are what the spec
	// allows -- not what this writer supports; see CreateContainer.
	nxDefaultBlockSize = 4096
	nxMinimumBlockSize = 4096
	nxMaximumBlockSize = 65536
)

// Container incompatible feature flags.
const (
	nxIncompatVersion2 = 0x0000000000000002
	nxIncompatFusion   = 0x0000000000000100
)

// Checkpoint flags.
const checkpointMapLast = 0x00000001

// Volume constants.
const (
	apfsMagic  = 0x42535041
	volnameLen = 256
)

// Volume feature / flag constants.
const (
	apfsFeatureHardlinkMapRecords = 0x00000002

	// apfsFeatureVolgrpSystemInoSpace declares that the volume belongs to a
	// volume group. It, not the group identifier, is what checkers consult to
	// decide membership, so the two must always be set together.
	apfsFeatureVolgrpSystemInoSpace = 0x00000010

	apfsFSUnencrypted = 0x00000001

	apfsIncompatCaseInsensitive          = 0x00000001
	apfsIncompatNormalizationInsensitive = 0x00000008
)

// Wrapped meta crypto state versions and protection classes.
const (
	wmcsMajorVersion = 5
	wmcsMinorVersion = 0

	protectionClassDirNone = 0
	protectionClassF       = 6
)

// Reaper flags.
const nrBHMFlag = 0x00000001

// Space manager device and free-queue array indexes.
const (
	sdMain  = 0
	sdTier2 = 1
	sdCount = 2

	sfqIP    = 0
	sfqMain  = 1
	sfqTier2 = 2
	sfqCount = 3
)

// Internal-pool bitmap constants.
const (
	spacemanIPBMTxMultiplier = 16
	spacemanIPBMIndexInvalid = 0xffff
)

// Sizes of on-disk structures (bytes), matching the __packed C layouts.
const (
	sizeofObjPhys              = 32
	sizeofBtreeNodePhys        = 56 // obj(32)+flags(2)+level(2)+nkeys(4)+4*nloc(16)
	sizeofBtreeInfo            = 40
	sizeofKvloc                = 8
	sizeofKvoff                = 4
	sizeofOmapKey              = 16
	sizeofOmapVal              = 16
	sizeofCheckpointMapping    = 40
	sizeofChunkInfo            = 32
	sizeofChunkInfoBlockHdr    = 40 // obj(32)+cib_index(4)+cib_chunk_info_count(4)
	sizeofCibAddrBlockHdr      = 40 // obj(32)+cab_index(4)+cab_cib_count(4)
	sizeofSpacemanFreeQueueKey = 16
	sizeofFusionMtKey          = 8
	sizeofFusionMtVal          = 16
	sizeofNXReaperPhys         = 112
	sizeofDrecVal              = 18 // file_id(8)+date_added(8)+flags(2)
	sizeofInodeVal             = 92 // ends at 0x5C (xfields)
	sizeofXfBlob               = 4
	sizeofXField               = 4
	sizeofInodeKey             = 8
	sizeofDrecKeyFixed         = 10 // hdr(8)+name_len(2)
	sizeofDrecHashedKeyFixed   = 12 // hdr(8)+name_len_and_hash(4)
	sizeofXattrKeyFixed        = 10 // hdr(8)+name_len(2)
	sizeofXattrValFixed        = 4  // flags(2)+xdata_len(2)

	// sizeofXattrDstream is j_xattr_dstream_t: xattr_obj_id(8) + j_dstream_t.
	sizeofXattrDstream = 8 + sizeofDstream

	// A sibling-link key is the object header plus the sibling id; its value is
	// the parent directory's id, the name length, and the name.
	sizeofSiblingLinkKey      = 16
	sizeofSiblingLinkValFixed = 10 // parent_id(8)+name_len(2)
	// A sibling-map record is keyed on the sibling id alone and names the
	// inode it stands for.
	sizeofSiblingMapKey = 8
	sizeofSiblingMapVal = 8

	// drecExtTypeSiblingID is the extended field on a directory entry naming
	// the sibling record for that particular name.
	drecExtTypeSiblingID = 1

	sizeofDstream       = 40 // size(8)+alloced_size(8)+default_crypto_id(8)+total_bytes_written(8)+total_bytes_read(8)
	sizeofDstreamIDVal  = 4  // refcnt(4)
	sizeofFileExtentKey = 16 // hdr(8)+logical_addr(8)
	sizeofFileExtentVal = 24 // len_and_flags(8)+phys_block_num(8)+crypto_id(8)
	sizeofPhysExtKey    = 8  // hdr(8)
	sizeofPhysExtVal    = 20 // len_and_kind(8)+owning_obj_id(8)+refcnt(4)
)

// S_IFDIR from <sys/stat.h>, used for directory mode bits.
const sIFDIR = 0o040000
