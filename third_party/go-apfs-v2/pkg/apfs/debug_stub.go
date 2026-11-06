// Debug stubs for non-debug builds
//go:build !debug
// +build !debug

package apfs

import (
	"encoding/binary"
	"io"
)

// Debug output enabled flag (always false in non-debug builds)
var DebugOutput = false

// PrintBTreeFlags is a no-op in non-debug builds
func PrintBTreeFlags(btreeFlags uint32) {}

// PrintBTreeNodeFlags is a no-op in non-debug builds
func PrintBTreeNodeFlags(btreeNodeFlags uint16) {}

// PrintCheckpointFlags is a no-op in non-debug builds
func PrintCheckpointFlags(checkpointFlags uint32) {}

// PrintContainerCompatibleFeaturesFlags is a no-op in non-debug builds
func PrintContainerCompatibleFeaturesFlags(compatibleFeaturesFlags uint64) {}

// PrintContainerIncompatibleFeaturesFlags is a no-op in non-debug builds
func PrintContainerIncompatibleFeaturesFlags(incompatibleFeaturesFlags uint64) {}

// PrintContainerReadOnlyCompatibleFeaturesFlags is a no-op in non-debug builds
func PrintContainerReadOnlyCompatibleFeaturesFlags(readOnlyCompatibleFeaturesFlags uint64) {}

// PrintDirectoryEntryFlags is a no-op in non-debug builds
func PrintDirectoryEntryFlags(directoryEntryFlags uint16) {}

// PrintExtendedAttributeFlags is a no-op in non-debug builds
func PrintExtendedAttributeFlags(extendedAttributeFlags uint16) {}

// PrintExtendedFieldFlags is a no-op in non-debug builds
func PrintExtendedFieldFlags(extendedFieldFlags uint8) {}

// PrintInodeFlags is a no-op in non-debug builds
func PrintInodeFlags(inodeFlags uint64) {}

// PrintVolumeCompatibleFeaturesFlags is a no-op in non-debug builds
func PrintVolumeCompatibleFeaturesFlags(compatibleFeaturesFlags uint64) {}

// PrintVolumeFlags is a no-op in non-debug builds
func PrintVolumeFlags(volumeFlags uint64) {}

// PrintVolumeIncompatibleFeaturesFlags is a no-op in non-debug builds
func PrintVolumeIncompatibleFeaturesFlags(incompatibleFeaturesFlags uint64) {}

// PrintVolumeReadOnlyCompatibleFeaturesFlags is a no-op in non-debug builds
func PrintVolumeReadOnlyCompatibleFeaturesFlags(readOnlyCompatibleFeaturesFlags uint64) {}

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

// PrintPOSIXTimeValue is a no-op in non-debug builds
func PrintPOSIXTimeValue(functionName, valueName string, byteStream []byte, byteOrder binary.ByteOrder, valueType string) error {
	return nil
}

// PrintGUIDValue is a no-op in non-debug builds
func PrintGUIDValue(functionName, valueName string, byteStream []byte, byteOrder binary.ByteOrder) error {
	return nil
}

// PrintReadOffsets is a no-op in non-debug builds
func PrintReadOffsets(reader io.ReaderAt, offsets []struct{ Offset, Size int64 }) error {
	return nil
}

// PrintData is a no-op in non-debug builds
func PrintData(data []byte, groupData bool) {}
