// Debug functions for APFS
//go:build debug
// +build debug

package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

// Debug output enabled flag
// Deprecated: Use setVerbose() and isVerbose() instead
var DebugOutput = true

// PrintBTreeFlags prints the B-tree flags for debugging
func PrintBTreeFlags(btreeFlags uint32) {
	if !isVerbose() {
		return
	}

	if (btreeFlags & 0x00000001) != 0 {
		notifyPrintf("\t(BTREE_UINT64_KEYS)\n")
	}
	if (btreeFlags & 0x00000002) != 0 {
		notifyPrintf("\t(BTREE_SEQUENTIAL_INSERT)\n")
	}
	if (btreeFlags & 0x00000004) != 0 {
		notifyPrintf("\t(BTREE_ALLOW_GHOSTS)\n")
	}
	if (btreeFlags & 0x00000008) != 0 {
		notifyPrintf("\t(BTREE_EPHEMERAL)\n")
	}
	if (btreeFlags & 0x00000010) != 0 {
		notifyPrintf("\t(BTREE_PHYSICAL)\n")
	}
	if (btreeFlags & 0x00000020) != 0 {
		notifyPrintf("\t(BTREE_NONPERSISTENT)\n")
	}
	if (btreeFlags & 0x00000040) != 0 {
		notifyPrintf("\t(BTREE_KV_NONALIGNED)\n")
	}
	if (btreeFlags & 0x00000080) != 0 {
		notifyPrintf("\t(BTREE_HASHED)\n")
	}
	if (btreeFlags & 0x00000100) != 0 {
		notifyPrintf("\tHas no object header (BTREE_NOHEADER)\n")
	}
}

// PrintBTreeNodeFlags prints the B-tree node flags for debugging
func PrintBTreeNodeFlags(btreeNodeFlags uint16) {
	if !isVerbose() {
		return
	}

	if (btreeNodeFlags & 0x0001) != 0 {
		notifyPrintf("\tIs root (BTNODE_ROOT)\n")
	}
	if (btreeNodeFlags & 0x0002) != 0 {
		notifyPrintf("\tIs leaf (BTNODE_LEAF)\n")
	}
	if (btreeNodeFlags & 0x0004) != 0 {
		notifyPrintf("\tHas fixed-size entry (BTNODE_FIXED_KV_SIZE)\n")
	}
	if (btreeNodeFlags & 0x0008) != 0 {
		notifyPrintf("\t(BTNODE_HASHED)\n")
	}
	if (btreeNodeFlags & 0x0010) != 0 {
		notifyPrintf("\t(BTNODE_NOHEADER)\n")
	}
	if (btreeNodeFlags & 0x8000) != 0 {
		notifyPrintf("\tIn transient state (BTNODE_CHECK_KOFF_INVAL)\n")
	}
}

// PrintCheckpointFlags prints the checkpoint flags for debugging
func PrintCheckpointFlags(checkpointFlags uint32) {
	if !isVerbose() {
		return
	}

	if (checkpointFlags & 0x00000001) != 0 {
		notifyPrintf("\t(CHECKPOINT_MAP_LAST)\n")
	}
}

// PrintContainerCompatibleFeaturesFlags prints the container compatible feature flags
func PrintContainerCompatibleFeaturesFlags(compatibleFeaturesFlags uint64) {
	if !isVerbose() {
		return
	}

	if (compatibleFeaturesFlags & 0x0000000000000001) != 0 {
		notifyPrintf("\t(NX_FEATURE_DEFRAG)\n")
	}
	if (compatibleFeaturesFlags & 0x0000000000000002) != 0 {
		notifyPrintf("\t(NX_FEATURE_LCFD)\n")
	}
}

// PrintContainerIncompatibleFeaturesFlags prints the container incompatible feature flags
func PrintContainerIncompatibleFeaturesFlags(incompatibleFeaturesFlags uint64) {
	if !isVerbose() {
		return
	}

	if (incompatibleFeaturesFlags & 0x0000000000000001) != 0 {
		notifyPrintf("\t(NX_INCOMPAT_VERSION1)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000002) != 0 {
		notifyPrintf("\t(NX_INCOMPAT_VERSION2)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000100) != 0 {
		notifyPrintf("\t(NX_INCOMPAT_FUSION)\n")
	}
}

// PrintContainerReadOnlyCompatibleFeaturesFlags prints the container read-only compatible feature flags
func PrintContainerReadOnlyCompatibleFeaturesFlags(readOnlyCompatibleFeaturesFlags uint64) {
	if !isVerbose() {
		return
	}
	// Currently there are no container read-only compatible feature flags defined
	_ = readOnlyCompatibleFeaturesFlags
}

// PrintDirectoryEntryFlags prints the directory entry flags for debugging
func PrintDirectoryEntryFlags(directoryEntryFlags uint16) {
	if !isVerbose() {
		return
	}

	switch directoryEntryFlags & 0x000f {
	case 0x0000:
		notifyPrintf("\t(DT_UNKNOWN)\n")
	case 0x0001:
		notifyPrintf("\t(DT_FIFO)\n")
	case 0x0002:
		notifyPrintf("\t(DT_CHR)\n")
	case 0x0004:
		notifyPrintf("\t(DT_DIR)\n")
	case 0x0006:
		notifyPrintf("\t(DT_BLK)\n")
	case 0x0008:
		notifyPrintf("\t(DT_REG)\n")
	case 0x000a:
		notifyPrintf("\t(DT_LNK)\n")
	case 0x000c:
		notifyPrintf("\t(DT_SOCK)\n")
	case 0x000e:
		notifyPrintf("\t(DT_WHT)\n")
	default:
		notifyPrintf("\tUnknown: 0x%04x\n", directoryEntryFlags&0x000f)
	}

	if (directoryEntryFlags & 0x0010) != 0 {
		notifyPrintf("\t(RESERVED_10)\n")
	}
}

// PrintExtendedAttributeFlags prints the extended attribute flags for debugging
func PrintExtendedAttributeFlags(extendedAttributeFlags uint16) {
	if !isVerbose() {
		return
	}

	if (extendedAttributeFlags & 0x0001) != 0 {
		notifyPrintf("\t(XATTR_DATA_STREAM)\n")
	}
	if (extendedAttributeFlags & 0x0002) != 0 {
		notifyPrintf("\t(XATTR_DATA_EMBEDDED)\n")
	}
	if (extendedAttributeFlags & 0x0004) != 0 {
		notifyPrintf("\t(XATTR_FILE_SYSTEM_OWNED)\n")
	}
	if (extendedAttributeFlags & 0x0008) != 0 {
		notifyPrintf("\t(XATTR_RESERVED_8)\n")
	}
}

// PrintExtendedFieldFlags prints the extended field flags for debugging
func PrintExtendedFieldFlags(extendedFieldFlags uint8) {
	if !isVerbose() {
		return
	}

	if (extendedFieldFlags & 0x01) != 0 {
		notifyPrintf("\t(XF_DATA_DEPENDENT)\n")
	}
	if (extendedFieldFlags & 0x02) != 0 {
		notifyPrintf("\t(XF_DO_NOT_COPY)\n")
	}
	if (extendedFieldFlags & 0x04) != 0 {
		notifyPrintf("\t(XF_RESERVED_4)\n")
	}
	if (extendedFieldFlags & 0x08) != 0 {
		notifyPrintf("\t(XF_CHILDREN_INHERIT)\n")
	}
	if (extendedFieldFlags & 0x10) != 0 {
		notifyPrintf("\t(XF_USER_FIELD)\n")
	}
	if (extendedFieldFlags & 0x20) != 0 {
		notifyPrintf("\t(XF_SYSTEM_FIELD)\n")
	}
	if (extendedFieldFlags & 0x40) != 0 {
		notifyPrintf("\t(XF_RESERVED_40)\n")
	}
	if (extendedFieldFlags & 0x80) != 0 {
		notifyPrintf("\t(XF_RESERVED_80)\n")
	}
}

// PrintInodeFlags prints the inode flags for debugging
func PrintInodeFlags(inodeFlags uint64) {
	if !isVerbose() {
		return
	}

	if (inodeFlags & 0x00000001) != 0 {
		notifyPrintf("\t(INODE_IS_APFS_PRIVATE)\n")
	}
	if (inodeFlags & 0x00000002) != 0 {
		notifyPrintf("\t(INODE_MAINTAIN_DIR_STATS)\n")
	}
	if (inodeFlags & 0x00000004) != 0 {
		notifyPrintf("\t(INODE_DIR_STATS_ORIGIN)\n")
	}
	if (inodeFlags & 0x00000008) != 0 {
		notifyPrintf("\t(INODE_PROT_CLASS_EXPLICIT)\n")
	}
	if (inodeFlags & 0x00000010) != 0 {
		notifyPrintf("\t(INODE_WAS_CLONED)\n")
	}
	if (inodeFlags & 0x00000020) != 0 {
		notifyPrintf("\t(INODE_FLAG_UNUSED)\n")
	}
	if (inodeFlags & 0x00000040) != 0 {
		notifyPrintf("\t(INODE_HAS_SECURITY_EA)\n")
	}
	if (inodeFlags & 0x00000080) != 0 {
		notifyPrintf("\t(INODE_BEING_TRUNCATED)\n")
	}
	if (inodeFlags & 0x00000100) != 0 {
		notifyPrintf("\t(INODE_HAS_FINDER_INFO)\n")
	}
	if (inodeFlags & 0x00000200) != 0 {
		notifyPrintf("\t(INODE_IS_SPARSE)\n")
	}
	if (inodeFlags & 0x00000400) != 0 {
		notifyPrintf("\t(INODE_WAS_EVER_CLONED)\n")
	}
	if (inodeFlags & 0x00000800) != 0 {
		notifyPrintf("\t(INODE_ACTIVE_FILE_TRIMMED)\n")
	}
	if (inodeFlags & 0x00001000) != 0 {
		notifyPrintf("\t(INODE_PINNED_TO_MAIN)\n")
	}
	if (inodeFlags & 0x00002000) != 0 {
		notifyPrintf("\t(INODE_PINNED_TO_TIER2)\n")
	}
	if (inodeFlags & 0x00004000) != 0 {
		notifyPrintf("\t(INODE_HAS_RSRC_FORK)\n")
	}
	if (inodeFlags & 0x00008000) != 0 {
		notifyPrintf("\t(INODE_NO_RSRC_FORK)\n")
	}
	if (inodeFlags & 0x00010000) != 0 {
		notifyPrintf("\t(INODE_ALLOCATION_SPILLEDOVER)\n")
	}
}

// PrintVolumeCompatibleFeaturesFlags prints the volume compatible feature flags
func PrintVolumeCompatibleFeaturesFlags(compatibleFeaturesFlags uint64) {
	if !isVerbose() {
		return
	}

	if (compatibleFeaturesFlags & 0x0000000000000001) != 0 {
		notifyPrintf("\t(APFS_FEATURE_DEFRAG_PRERELEASE)\n")
	}
	if (compatibleFeaturesFlags & 0x0000000000000002) != 0 {
		notifyPrintf("\t(APFS_FEATURE_HARDLINK_MAP_RECORDS)\n")
	}
	if (compatibleFeaturesFlags & 0x0000000000000004) != 0 {
		notifyPrintf("\t(APFS_FEATURE_DEFRAG)\n")
	}
	if (compatibleFeaturesFlags & 0x0000000000000008) != 0 {
		notifyPrintf("\t(APFS_FEATURE_STRICTATIME)\n")
	}
	if (compatibleFeaturesFlags & 0x0000000000000010) != 0 {
		notifyPrintf("\t(APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE)\n")
	}
}

// PrintVolumeFlags prints the volume flags for debugging
func PrintVolumeFlags(volumeFlags uint64) {
	if !isVerbose() {
		return
	}

	if (volumeFlags & 0x0000000000000001) != 0 {
		notifyPrintf("\t(APFS_FS_UNENCRYPTED)\n")
	}
	if (volumeFlags & 0x0000000000000002) != 0 {
		notifyPrintf("\t(APFS_FS_EFFACEABLE)\n")
	}
	if (volumeFlags & 0x0000000000000004) != 0 {
		notifyPrintf("\t(APFS_FS_RESERVED_4)\n")
	}
	if (volumeFlags & 0x0000000000000008) != 0 {
		notifyPrintf("\t(APFS_FS_ONEKEY)\n")
	}
	if (volumeFlags & 0x0000000000000010) != 0 {
		notifyPrintf("\t(APFS_FS_SPILLEDOVER)\n")
	}
	if (volumeFlags & 0x0000000000000020) != 0 {
		notifyPrintf("\t(APFS_FS_RUN_SPILLOVER_CLEANER)\n")
	}
}

// PrintVolumeIncompatibleFeaturesFlags prints the volume incompatible feature flags
func PrintVolumeIncompatibleFeaturesFlags(incompatibleFeaturesFlags uint64) {
	if !isVerbose() {
		return
	}

	if (incompatibleFeaturesFlags & 0x0000000000000001) != 0 {
		notifyPrintf("\t(APFS_INCOMPAT_CASE_INSENSITIVE)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000002) != 0 {
		notifyPrintf("\t(APFS_INCOMPAT_DATALESS_SNAPS)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000004) != 0 {
		notifyPrintf("\t(APFS_INCOMPAT_ENC_ROLLED)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000008) != 0 {
		notifyPrintf("\t(APFS_INCOMPAT_NORMALIZATION_INSENSITIVE)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000010) != 0 {
		notifyPrintf("\t(APFS_INCOMPAT_INCOMPLETE_RESTORE)\n")
	}
	if (incompatibleFeaturesFlags & 0x0000000000000020) != 0 {
		notifyPrintf("\t(APFS_INCOMPAT_SEALED_VOLUME)\n")
	}
}

// PrintVolumeReadOnlyCompatibleFeaturesFlags prints the volume read-only compatible feature flags
func PrintVolumeReadOnlyCompatibleFeaturesFlags(readOnlyCompatibleFeaturesFlags uint64) {
	if !isVerbose() {
		return
	}
	// Currently there are no volume read-only compatible feature flags defined
	_ = readOnlyCompatibleFeaturesFlags
}

// DirectoryEntryExtendedFieldTypeName returns the name of the directory entry record extended field type
func DirectoryEntryExtendedFieldTypeName(extendedFieldType uint8) string {
	switch extendedFieldType {
	case 1:
		return "(DREC_EXT_TYPE_SIBLING_ID)"
	}
	return "Unknown"
}

// InodeExtendedFieldTypeName returns the name of the inode extended field type
func InodeExtendedFieldTypeName(extendedFieldType uint8) string {
	switch extendedFieldType {
	case 1:
		return "(INO_EXT_TYPE_SNAP_XID)"
	case 2:
		return "(INO_EXT_TYPE_DELTA_TREE_OID)"
	case 3:
		return "(INO_EXT_TYPE_DOCUMENT_ID)"
	case 4:
		return "(INO_EXT_TYPE_NAME)"
	case 5:
		return "(INO_EXT_TYPE_PREV_FSIZE)"
	case 6:
		return "(INO_EXT_TYPE_RESERVED_6)"
	case 7:
		return "(INO_EXT_TYPE_FINDER_INFO)"
	case 8:
		return "(INO_EXT_TYPE_DSTREAM)"
	case 9:
		return "(INO_EXT_TYPE_RESERVED_9)"
	case 10:
		return "(INO_EXT_TYPE_DIR_STATS_KEY)"
	case 11:
		return "(INO_EXT_TYPE_FS_UUID)"
	case 12:
		return "(INO_EXT_TYPE_RESERVED_12)"
	case 13:
		return "(INO_EXT_TYPE_SPARSE_BYTES)"
	case 14:
		return "(INO_EXT_TYPE_RDEV)"
	case 15:
		return "(INO_EXT_TYPE_PURGEABLE_FLAGS)"
	case 16:
		return "(INO_EXT_TYPE_ORIG_SYNC_ROOT_ID)"
	}
	return "Unknown"
}

// PrintPOSIXTimeValue prints a POSIX time value for debugging
func PrintPOSIXTimeValue(functionName, valueName string, byteStream []byte, byteOrder binary.ByteOrder, valueType string) error {
	if !isVerbose() {
		return nil
	}

	if len(byteStream) < 8 {
		return fmt.Errorf("invalid byte stream size: %d", len(byteStream))
	}

	var timestamp int64
	if byteOrder == binary.LittleEndian {
		timestamp = int64(binary.LittleEndian.Uint64(byteStream))
	} else {
		timestamp = int64(binary.BigEndian.Uint64(byteStream))
	}

	// Handle nanosecond timestamps (APFS uses nanoseconds since epoch)
	var t time.Time
	if valueType == "nanoseconds" {
		t = time.Unix(0, timestamp)
	} else {
		t = time.Unix(timestamp, 0)
	}

	notifyPrintf("%s: %s: %s UTC\n", functionName, valueName, t.UTC().Format("2006-01-02 15:04:05"))

	return nil
}

// PrintGUIDValue prints a GUID/UUID value for debugging
func PrintGUIDValue(functionName, valueName string, byteStream []byte, byteOrder binary.ByteOrder) error {
	if !isVerbose() {
		return nil
	}

	if len(byteStream) < 16 {
		return fmt.Errorf("invalid byte stream size for GUID: %d", len(byteStream))
	}

	// Parse UUID from byte stream
	var guidBytes [16]byte
	copy(guidBytes[:], byteStream[:16])

	// Handle byte order for UUID parsing
	// UUIDs are stored in mixed-endian format in APFS
	if byteOrder == binary.LittleEndian {
		// Swap first three groups (time_low, time_mid, time_hi_and_version)
		guidBytes[0], guidBytes[3] = guidBytes[3], guidBytes[0]
		guidBytes[1], guidBytes[2] = guidBytes[2], guidBytes[1]
		guidBytes[4], guidBytes[5] = guidBytes[5], guidBytes[4]
		guidBytes[6], guidBytes[7] = guidBytes[7], guidBytes[6]
	}

	guid, err := uuid.FromBytes(guidBytes[:])
	if err != nil {
		return fmt.Errorf("unable to parse GUID: %w", err)
	}

	notifyPrintf("%s: %s: %s\n", functionName, valueName, guid.String())

	return nil
}

// PrintReadOffsets prints the read offsets for debugging I/O operations
func PrintReadOffsets(reader io.ReaderAt, offsets []struct{ Offset, Size int64 }) error {
	if !isVerbose() {
		return nil
	}

	if reader == nil {
		return fmt.Errorf("invalid reader")
	}

	notifyPrintf("Offsets read:\n")

	for i, offset := range offsets {
		notifyPrintf("%08d ( 0x%08x ) - %08d ( 0x%08x ) size: %d\n",
			offset.Offset,
			offset.Offset,
			offset.Offset+offset.Size,
			offset.Offset+offset.Size,
			offset.Size)

		_ = i // avoid unused variable
	}

	notifyPrintf("\n")

	return nil
}

// PrintData prints data in hexadecimal format for debugging
func PrintData(data []byte, groupData bool) {
	if !isVerbose() {
		return
	}

	const bytesPerLine = 16
	for i := 0; i < len(data); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}

		notifyPrintf("\t%08x: ", i)

		for j := i; j < end; j++ {
			notifyPrintf("%02x ", data[j])
			if groupData && (j-i+1)%8 == 0 && j < end-1 {
				notifyPrintf(" ")
			}
		}

		remainder := bytesPerLine - (end - i)
		for j := 0; j < remainder; j++ {
			notifyPrintf("   ")
		}
		if groupData && remainder > 0 {
			notifyPrintf(" ")
		}

		notifyPrintf(" |")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] <= 126 {
				notifyPrintf("%c", data[j])
			} else {
				notifyPrintf(".")
			}
		}
		notifyPrintf("|\n")
	}
}
