package apfs

// File-system record types (Apple: j_obj_types, "The type of a file-system
// record"). The value occupies the high 4 bits of j_key_t.obj_id_and_type.
const (
	FileSystemRecordTypeAny               uint8 = 0x00
	FileSystemRecordTypeSnapMetadata      uint8 = 0x01
	FileSystemRecordTypeExtent            uint8 = 0x02 // physical extent, not file extent
	FileSystemRecordTypeInode             uint8 = 0x03
	FileSystemRecordTypeExtendedAttribute uint8 = 0x04
	FileSystemRecordTypeSiblingLink       uint8 = 0x05
	FileSystemRecordTypeDStreamID         uint8 = 0x06
	FileSystemRecordTypeCryptoState       uint8 = 0x07
	FileSystemRecordTypeFileExtent        uint8 = 0x08
	FileSystemRecordTypeDirectoryEntry    uint8 = 0x09
	FileSystemRecordTypeDirectoryStats    uint8 = 0x0a
	FileSystemRecordTypeSnapshotName      uint8 = 0x0b
	FileSystemRecordTypeSiblingMap        uint8 = 0x0c
	FileSystemRecordTypeFileInfo          uint8 = 0x0d
	FileSystemRecordTypeMaxValid          uint8 = 0x0d
	FileSystemRecordTypeInvalid           uint8 = 0x0f
)

// FileSystemRecordTypeName returns Apple's j_obj_types constant name for a
// file-system record type, or "UNKNOWN" if the value is not one Apple defines.
func FileSystemRecordTypeName(recordType uint8) string {
	switch recordType {
	case FileSystemRecordTypeAny:
		return "APFS_TYPE_ANY"
	case FileSystemRecordTypeSnapMetadata:
		return "APFS_TYPE_SNAP_METADATA"
	case FileSystemRecordTypeExtent:
		return "APFS_TYPE_EXTENT"
	case FileSystemRecordTypeInode:
		return "APFS_TYPE_INODE"
	case FileSystemRecordTypeExtendedAttribute:
		return "APFS_TYPE_XATTR"
	case FileSystemRecordTypeSiblingLink:
		return "APFS_TYPE_SIBLING_LINK"
	case FileSystemRecordTypeDStreamID:
		return "APFS_TYPE_DSTREAM_ID"
	case FileSystemRecordTypeCryptoState:
		return "APFS_TYPE_CRYPTO_STATE"
	case FileSystemRecordTypeFileExtent:
		return "APFS_TYPE_FILE_EXTENT"
	case FileSystemRecordTypeDirectoryEntry:
		return "APFS_TYPE_DIR_REC"
	case FileSystemRecordTypeDirectoryStats:
		return "APFS_TYPE_DIR_STATS"
	case FileSystemRecordTypeSnapshotName:
		return "APFS_TYPE_SNAP_NAME"
	case FileSystemRecordTypeSiblingMap:
		return "APFS_TYPE_SIBLING_MAP"
	case FileSystemRecordTypeFileInfo:
		return "APFS_TYPE_FILE_INFO"
	case FileSystemRecordTypeInvalid:
		return "APFS_TYPE_INVALID"
	default:
		return "UNKNOWN"
	}
}
