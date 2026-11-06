package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

// ModifiedByInfo represents who last formatted or modified the volume
// Corresponds to apfs_modified_by_t in APFS spec
type ModifiedByInfo struct {
	// ID/name of the software (32 bytes)
	ID [32]byte
	// Timestamp when modified (8 bytes)
	Timestamp uint64
	// Last transaction ID (8 bytes)
	LastTransactionID uint64
}

// VolumeSuperblock represents the APFS volume superblock structure
type VolumeSuperblock struct {
	// The object checksum
	// Consists of 8 bytes
	Checksum uint64

	// The object identifier
	// Consists of 8 bytes
	OID uint64

	// The object transaction identifier
	// Consists of 8 bytes
	XID uint64

	// The object type
	// Consists of 4 bytes
	ObjectType uint32

	// The object subtype
	// Consists of 4 bytes
	ObjectSubtype uint32

	// The file system signature
	// Consists of 4 bytes
	// Contains: "APSB"
	Signature [4]byte

	// The file system index (apfs_fs_index)
	// Consists of 4 bytes
	FSIndex uint32

	// Compatible features flags
	// Consists of 8 bytes
	CompatibleFeaturesFlags uint64

	// Read only compatible features flags
	// Consists of 8 bytes
	ReadOnlyCompatibleFeaturesFlags uint64

	// Incompatible features flags
	// Consists of 8 bytes
	IncompatibleFeaturesFlags uint64

	// Last unmount time (apfs_unmount_time) - nanoseconds since Unix epoch
	// Consists of 8 bytes
	UnmountTime uint64

	// The number of reserved blocks
	// Consists of 8 bytes
	NumberOfReservedBlocks uint64

	// The number of quota blocks
	// Consists of 8 bytes
	NumberOfQuotaBlocks uint64

	// The number of allocated blocks (apfs_fs_alloc_count)
	// Consists of 8 bytes
	NumberOfAllocatedBlocks uint64

	// Information about how the volume encryption key (VEK) is used to
	// encrypt a file (apfs_meta_crypto, wrapped_meta_crypto_state_t).
	// Consists of 20 bytes
	MetaCryptoMajorVersion    uint16
	MetaCryptoMinorVersion    uint16
	MetaCryptoFlags           uint32
	MetaCryptoPersistentClass uint32
	MetaCryptoKeyOSVersion    uint32
	MetaCryptoKeyRevision     uint16
	MetaCryptoUnused          uint16

	// The file system root tree object type
	// Consists of 4 bytes
	RootTreeType uint32

	// The extentref tree object type
	// Consists of 4 bytes
	ExtentrefTreeType uint32

	// The snapshot metadata tree object type
	// Consists of 4 bytes
	SnapMetaTreeType uint32

	// The object map block number
	// Consists of 8 bytes
	OmapOID uint64

	// The file system root object identifier
	// Consists of 8 bytes
	RootTreeOID uint64

	// The extentref tree block number
	// Consists of 8 bytes
	ExtentrefTreeOID uint64

	// The snapshot metadata tree block number
	// Consists of 8 bytes
	SnapMetaTreeOID uint64

	// Revert to transaction identifier (apfs_revert_to_xid)
	// Consists of 8 bytes
	RevertToXID uint64

	// Revert to superblock object identifier (apfs_revert_to_sblock_oid)
	// Consists of 8 bytes
	RevertToSblockOID uint64

	// The next file system object identifier
	// Consists of 8 bytes
	NextObjID uint64

	// Number of regular files (apfs_num_files)
	// Consists of 8 bytes
	NumberOfFiles uint64

	// Number of directories (apfs_num_directories)
	// Consists of 8 bytes
	NumberOfDirectories uint64

	// Number of symbolic links (apfs_num_symlinks)
	// Consists of 8 bytes
	NumberOfSymlinks uint64

	// Number of other file system objects (apfs_num_other_fsobjects)
	// Consists of 8 bytes
	NumberOfOtherFileSystemObjects uint64

	// Number of snapshots (apfs_num_snapshots)
	// Consists of 8 bytes
	SnapshotCount uint64

	// Total blocks allocated ever (apfs_total_block_alloced)
	// Consists of 8 bytes
	TotalBlocksAllocated uint64

	// Total blocks freed ever (apfs_total_blocks_freed)
	// Consists of 8 bytes
	TotalBlocksFreed uint64

	// The volume identifier
	// Consists of 16 bytes
	// Contains an UUID
	VolumeUUID [16]byte

	// The volume (last) modification date and time
	// Consists of 8 bytes
	ModificationTime uint64

	// The volume flags
	// Consists of 8 bytes
	VolumeFlags uint64

	// Who formatted the volume (apfs_formatted_by)
	// Offset 272-320, consists of 48 bytes (32 + 8 + 8)
	FormattedBy ModifiedByInfo

	// History of who modified the volume (apfs_modified_by)
	// Offset 320-704, consists of 8 * 48 = 384 bytes
	ModifiedBy [8]ModifiedByInfo

	// The volume name
	// Consists of 256 bytes
	VolumeName [256]byte

	// The next (available) document identifier
	// Consists of 4 bytes
	NextDocID uint32

	// The volume's role (apfs_role)
	// Consists of 2 bytes
	Role uint16

	// Reserved (reserved)
	// Consists of 2 bytes
	Reserved uint16

	// The transaction identifier of a snapshot that the volume will revert
	// to (apfs_root_to_xid)
	// Consists of 8 bytes
	RootToXID uint64

	// The object identifier of the encryption rolling state (apfs_er_state_oid)
	// Consists of 8 bytes
	ERStateOID uint64

	// The largest object identifier used by this volume at the time it was
	// last cloned (apfs_cloneinfo_id_epoch)
	// Consists of 8 bytes
	CloneinfoIDEpoch uint64

	// The transaction identifier matching CloneinfoIDEpoch (apfs_cloneinfo_xid)
	// Consists of 8 bytes
	CloneinfoXID uint64

	// The object identifier of the extended snapshot metadata
	// (apfs_snap_meta_ext_oid)
	// Consists of 8 bytes
	SnapMetaExtOID uint64

	// The identifier of the volume group this volume belongs to
	// (apfs_volume_group_id), or the zero UUID when it belongs to none.
	// Consists of 16 bytes
	VolumeGroupID [16]byte

	// The object identifier of the integrity metadata that seals the volume
	// (apfs_integrity_meta_oid). Zero on an unsealed volume.
	IntegrityMetaOID uint64

	// The object identifier of the file extent tree (apfs_fext_tree_oid).
	// Sealed volumes keep their file extents here; zero when absent.
	FextTreeOID uint64

	// The object type of the file extent tree (apfs_fext_tree_type).
	FextTreeType uint32

	// Parsed volume name as string (not part of binary structure)
	volumeName string
}

// Volume superblock methods

// NewVolumeSuperblock creates a new volume superblock
func NewVolumeSuperblock() *VolumeSuperblock {
	return &VolumeSuperblock{}
}

// ReadFrom reads the volume superblock from a file at the specified offset
func (vs *VolumeSuperblock) ReadFrom(reader io.ReaderAt, fileOffset int64, isSnapshot bool) error {
	if vs == nil {
		return fmt.Errorf("invalid volume superblock")
	}

	if DebugOutput {
		fmt.Printf("Reading volume superblock at offset: %d (0x%08x)\n", fileOffset, fileOffset)
	}

	// Read 4096 bytes (size of volume superblock)
	data := make([]byte, 4096)
	n, err := reader.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read volume superblock data at offset %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}
	if n != 4096 {
		return fmt.Errorf("unable to read volume superblock data at offset %d (0x%08x): read %d bytes, expected 4096",
			fileOffset, fileOffset, n)
	}

	// Parse the data
	if err := vs.ReadData(data, isSnapshot); err != nil {
		return fmt.Errorf("unable to read volume superblock data: %w", err)
	}

	return nil
}

// ReadData reads the volume superblock from binary data
func (vs *VolumeSuperblock) ReadData(data []byte, isSnapshot bool) error {
	if vs == nil {
		return fmt.Errorf("invalid volume superblock")
	}
	if data == nil {
		return fmt.Errorf("invalid data")
	}
	if len(data) < 1024 {
		return fmt.Errorf("invalid data size: %d bytes (minimum 1024)", len(data))
	}

	// Determine expected object type based on snapshot flag
	var expectedObjectType uint32
	if isSnapshot {
		expectedObjectType = 0x4000000d // Snapshot volume superblock
	} else {
		expectedObjectType = 0x0000000d // Regular volume superblock
	}

	// Parse object header (first 32 bytes)
	vs.Checksum = binary.LittleEndian.Uint64(data[0:8])
	vs.OID = binary.LittleEndian.Uint64(data[8:16])
	vs.XID = binary.LittleEndian.Uint64(data[16:24])
	vs.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	vs.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	// Validate object type
	if vs.ObjectType != expectedObjectType {
		return fmt.Errorf("invalid object type: 0x%08x (expected 0x%08x)", vs.ObjectType, expectedObjectType)
	}

	// Validate object subtype (must be 0)
	if vs.ObjectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x (expected 0x00000000)", vs.ObjectSubtype)
	}

	// Parse signature (offset 32, 4 bytes)
	copy(vs.Signature[:], data[32:36])

	// Validate signature ("APSB")
	expectedSignature := [4]byte{'A', 'P', 'S', 'B'}
	if vs.Signature != expectedSignature {
		return fmt.Errorf("invalid signature: %s (expected APSB)", string(vs.Signature[:]))
	}

	// Parse remaining fields
	vs.FSIndex = binary.LittleEndian.Uint32(data[36:40])
	vs.CompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[40:48])
	vs.ReadOnlyCompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[48:56])
	vs.IncompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[56:64])
	vs.UnmountTime = binary.LittleEndian.Uint64(data[64:72])
	vs.NumberOfReservedBlocks = binary.LittleEndian.Uint64(data[72:80])
	vs.NumberOfQuotaBlocks = binary.LittleEndian.Uint64(data[80:88])
	vs.NumberOfAllocatedBlocks = binary.LittleEndian.Uint64(data[88:96])
	// apfs_meta_crypto (wrapped_meta_crypto_state_t), offsets 96..116
	vs.MetaCryptoMajorVersion = binary.LittleEndian.Uint16(data[96:98])
	vs.MetaCryptoMinorVersion = binary.LittleEndian.Uint16(data[98:100])
	vs.MetaCryptoFlags = binary.LittleEndian.Uint32(data[100:104])
	vs.MetaCryptoPersistentClass = binary.LittleEndian.Uint32(data[104:108])
	vs.MetaCryptoKeyOSVersion = binary.LittleEndian.Uint32(data[108:112])
	vs.MetaCryptoKeyRevision = binary.LittleEndian.Uint16(data[112:114])
	vs.MetaCryptoUnused = binary.LittleEndian.Uint16(data[114:116])
	vs.RootTreeType = binary.LittleEndian.Uint32(data[116:120])
	vs.ExtentrefTreeType = binary.LittleEndian.Uint32(data[120:124])
	vs.SnapMetaTreeType = binary.LittleEndian.Uint32(data[124:128])
	vs.OmapOID = binary.LittleEndian.Uint64(data[128:136])
	vs.RootTreeOID = binary.LittleEndian.Uint64(data[136:144])
	vs.ExtentrefTreeOID = binary.LittleEndian.Uint64(data[144:152])
	vs.SnapMetaTreeOID = binary.LittleEndian.Uint64(data[152:160])
	vs.RevertToXID = binary.LittleEndian.Uint64(data[160:168])
	vs.RevertToSblockOID = binary.LittleEndian.Uint64(data[168:176])
	vs.NextObjID = binary.LittleEndian.Uint64(data[176:184])
	vs.NumberOfFiles = binary.LittleEndian.Uint64(data[184:192])
	vs.NumberOfDirectories = binary.LittleEndian.Uint64(data[192:200])
	vs.NumberOfSymlinks = binary.LittleEndian.Uint64(data[200:208])
	vs.NumberOfOtherFileSystemObjects = binary.LittleEndian.Uint64(data[208:216])
	vs.SnapshotCount = binary.LittleEndian.Uint64(data[216:224])
	vs.TotalBlocksAllocated = binary.LittleEndian.Uint64(data[224:232])
	vs.TotalBlocksFreed = binary.LittleEndian.Uint64(data[232:240])

	// Volume identifier (offset 240, 16 bytes UUID)
	copy(vs.VolumeUUID[:], data[240:256])

	// Modification time (offset 256, 8 bytes)
	vs.ModificationTime = binary.LittleEndian.Uint64(data[256:264])

	// Volume flags (offset 264, 8 bytes)
	vs.VolumeFlags = binary.LittleEndian.Uint64(data[264:272])

	// FormattedBy (offset 272-320, 48 bytes)
	copy(vs.FormattedBy.ID[:], data[272:304])
	vs.FormattedBy.Timestamp = binary.LittleEndian.Uint64(data[304:312])
	vs.FormattedBy.LastTransactionID = binary.LittleEndian.Uint64(data[312:320])

	// ModifiedBy[8] (offset 320-704, 384 bytes = 8 * 48 bytes)
	for i := 0; i < 8; i++ {
		offset := 320 + (i * 48)
		copy(vs.ModifiedBy[i].ID[:], data[offset:offset+32])
		vs.ModifiedBy[i].Timestamp = binary.LittleEndian.Uint64(data[offset+32 : offset+40])
		vs.ModifiedBy[i].LastTransactionID = binary.LittleEndian.Uint64(data[offset+40 : offset+48])
	}

	// Volume name (offset 704, 256 bytes - UTF-8 string)
	copy(vs.VolumeName[:], data[704:960])

	// Parse and store the volume name as a string
	// Find null terminator in volume name
	nullIndex := bytes.IndexByte(vs.VolumeName[:], 0)
	if nullIndex >= 0 {
		vs.volumeName = string(vs.VolumeName[:nullIndex])
	} else {
		vs.volumeName = string(vs.VolumeName[:])
	}

	// Next document identifier (offset 960, 4 bytes)
	vs.NextDocID = binary.LittleEndian.Uint32(data[960:964])

	vs.Role = binary.LittleEndian.Uint16(data[964:966])
	vs.Reserved = binary.LittleEndian.Uint16(data[966:968])
	vs.RootToXID = binary.LittleEndian.Uint64(data[968:976])
	vs.ERStateOID = binary.LittleEndian.Uint64(data[976:984])
	vs.CloneinfoIDEpoch = binary.LittleEndian.Uint64(data[984:992])
	vs.CloneinfoXID = binary.LittleEndian.Uint64(data[992:1000])
	vs.SnapMetaExtOID = binary.LittleEndian.Uint64(data[1000:1008])

	// The volume group identifier ends exactly at the 1024-byte minimum this
	// function requires, so no size check is needed. The next field,
	// apfs_integrity_meta_oid at offset 1024, would need that minimum raised.
	copy(vs.VolumeGroupID[:], data[1008:1024])

	// Sealed-volume fields trail apfs_volume_group_id at offset 1024. Only
	// read them when the caller supplied enough bytes: ReadData's documented
	// minimum is the pre-sealing 1024-byte prefix.
	if len(data) >= 1032 {
		vs.IntegrityMetaOID = binary.LittleEndian.Uint64(data[1024:1032])
	}
	if len(data) >= 1040 {
		vs.FextTreeOID = binary.LittleEndian.Uint64(data[1032:1040])
	}
	if len(data) >= 1044 {
		vs.FextTreeType = binary.LittleEndian.Uint32(data[1040:1044])
	}

	return nil
}

// VolumeGroupIdentifier retrieves the identifier of the volume group this
// volume belongs to (apfs_volume_group_id). The zero UUID means the volume
// belongs to no group.
func (vs *VolumeSuperblock) VolumeGroupIdentifier() ([16]byte, error) {
	if vs == nil {
		return [16]byte{}, fmt.Errorf("invalid volume superblock")
	}
	return vs.VolumeGroupID, nil
}

// VolumeIdentifier retrieves the volume identifier (UUID)
func (vs *VolumeSuperblock) VolumeIdentifier() ([16]byte, error) {
	if vs == nil {
		return [16]byte{}, fmt.Errorf("invalid volume superblock")
	}
	return vs.VolumeUUID, nil
}

// FileSystemIndex retrieves the file system index
func (vs *VolumeSuperblock) FileSystemIndex() (uint32, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.FSIndex, nil
}

// RevertToTransactionIdentifier retrieves the revert-to transaction identifier
func (vs *VolumeSuperblock) RevertToTransactionIdentifier() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.RevertToXID, nil
}

// RevertToSuperblockObjectIdentifier retrieves the revert-to superblock object identifier
func (vs *VolumeSuperblock) RevertToSuperblockObjectIdentifier() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.RevertToSblockOID, nil
}

// NumberOfSnapshots retrieves the number of snapshots
func (vs *VolumeSuperblock) NumberOfSnapshots() (uint64, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	return vs.SnapshotCount, nil
}

// UTF8VolumeNameSize retrieves the size of the UTF-8 encoded volume name
// The returned size includes the end of string character
func (vs *VolumeSuperblock) UTF8VolumeNameSize() (int, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}
	// Return the length of the parsed name plus 1 for null terminator
	return len(vs.volumeName) + 1, nil
}

// UTF8VolumeName retrieves the UTF-8 encoded volume name
func (vs *VolumeSuperblock) UTF8VolumeName() (string, error) {
	if vs == nil {
		return "", fmt.Errorf("invalid volume superblock")
	}
	return vs.volumeName, nil
}

// UTF16VolumeNameSize retrieves the size of the UTF-16 encoded volume name
// The returned size includes the end of string character
func (vs *VolumeSuperblock) UTF16VolumeNameSize() (int, error) {
	if vs == nil {
		return 0, fmt.Errorf("invalid volume superblock")
	}

	// Convert UTF-8 string to UTF-16
	runes := []rune(vs.volumeName)
	utf16Data := utf16.Encode(runes)

	// Return the length plus 1 for null terminator
	return len(utf16Data) + 1, nil
}

// UTF16VolumeName retrieves the UTF-16 encoded volume name
func (vs *VolumeSuperblock) UTF16VolumeName() ([]uint16, error) {
	if vs == nil {
		return nil, fmt.Errorf("invalid volume superblock")
	}

	// Convert UTF-8 string to UTF-16
	runes := []rune(vs.volumeName)
	utf16Data := utf16.Encode(runes)

	// Add null terminator
	result := make([]uint16, len(utf16Data)+1)
	copy(result, utf16Data)
	result[len(utf16Data)] = 0

	return result, nil
}

// FormattedByString retrieves who formatted this volume
func (vs *VolumeSuperblock) FormattedByString() string {
	if vs == nil {
		return ""
	}
	// Find the null terminator
	for i, b := range vs.FormattedBy.ID {
		if b == 0 {
			return string(vs.FormattedBy.ID[:i])
		}
	}
	return string(vs.FormattedBy.ID[:])
}

// LastModifiedBy retrieves who last modified this volume (most recent entry)
func (vs *VolumeSuperblock) LastModifiedBy() string {
	if vs == nil {
		return ""
	}
	// Find the most recent non-empty entry
	for i := 7; i >= 0; i-- {
		// Check if this entry has data
		hasData := false
		for _, b := range vs.ModifiedBy[i].ID {
			if b != 0 {
				hasData = true
				break
			}
		}
		if hasData {
			// Find the null terminator
			for j, b := range vs.ModifiedBy[i].ID {
				if b == 0 {
					return string(vs.ModifiedBy[i].ID[:j])
				}
			}
			return string(vs.ModifiedBy[i].ID[:])
		}
	}
	return ""
}

// ModifiedByHistory retrieves the full modification history
// Returns a slice of strings from most recent to oldest, excluding empty entries
func (vs *VolumeSuperblock) ModifiedByHistory() []string {
	if vs == nil {
		return nil
	}

	history := make([]string, 0, 8)

	// Iterate from most recent (7) to oldest (0)
	for i := 7; i >= 0; i-- {
		// Check if this entry has data
		hasData := false
		for _, b := range vs.ModifiedBy[i].ID {
			if b != 0 {
				hasData = true
				break
			}
		}

		if hasData {
			// Find the null terminator and extract the string
			var modifiedBy string
			for j, b := range vs.ModifiedBy[i].ID {
				if b == 0 {
					modifiedBy = string(vs.ModifiedBy[i].ID[:j])
					break
				}
			}
			if modifiedBy == "" {
				modifiedBy = string(vs.ModifiedBy[i].ID[:])
			}
			history = append(history, modifiedBy)
		}
	}

	return history
}
