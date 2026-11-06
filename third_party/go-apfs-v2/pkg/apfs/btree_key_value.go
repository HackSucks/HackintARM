package apfs

import (
	"encoding/binary"
	"fmt"
)

// File system B-tree data types
// Based on APFS specification and verified against go-apfs implementation
// ExtractDataTypeFromKey extracts the data type from a file system B-tree key
// The data type is stored in the upper 4 bits of the file system identifier
func ExtractDataTypeFromKey(keyData []byte) (uint8, error) {
	if len(keyData) < 8 {
		return 0, fmt.Errorf("invalid key data size: expected at least 8 bytes, got %d", len(keyData))
	}

	fileSystemIdentifier := binary.LittleEndian.Uint64(keyData[0:8])

	// Data type is in bits 60-63 (upper 4 bits)
	dataType := uint8((fileSystemIdentifier >> 60) & 0x0f)

	return dataType, nil
}

// ExtractIdentifierFromKey extracts the object identifier from a file system B-tree key
// The identifier is stored in the lower 60 bits of the file system identifier
func ExtractIdentifierFromKey(keyData []byte) (uint64, error) {
	if len(keyData) < 8 {
		return 0, fmt.Errorf("invalid key data size: expected at least 8 bytes, got %d", len(keyData))
	}

	fileSystemIdentifier := binary.LittleEndian.Uint64(keyData[0:8])

	// Object identifier is in bits 0-59 (lower 60 bits)
	identifier := fileSystemIdentifier & 0x0fffffffffffffff

	return identifier, nil
}

// CompareFileSystemKeys compares two file system B-tree keys
// Returns <0 if key1 < key2, 0 if equal, >0 if key1 > key2
func CompareFileSystemKeys(key1Data []byte, key2Data []byte, dataType uint8) int {
	if len(key1Data) < 8 || len(key2Data) < 8 {
		return 0
	}

	// Extract identifiers
	fsid1 := binary.LittleEndian.Uint64(key1Data[0:8])
	fsid2 := binary.LittleEndian.Uint64(key2Data[0:8])

	// Compare identifiers (lower 60 bits)
	id1 := fsid1 & 0x0fffffffffffffff
	id2 := fsid2 & 0x0fffffffffffffff

	if id1 < id2 {
		return -1
	}
	if id1 > id2 {
		return 1
	}

	// If identifiers are equal, compare based on data type
	switch dataType {
	case FileSystemRecordTypeFileExtent:
		// For file extents, also compare logical address
		if len(key1Data) >= 16 && len(key2Data) >= 16 {
			logicalAddr1 := binary.LittleEndian.Uint64(key1Data[8:16])
			logicalAddr2 := binary.LittleEndian.Uint64(key2Data[8:16])

			if logicalAddr1 < logicalAddr2 {
				return -1
			}
			if logicalAddr1 > logicalAddr2 {
				return 1
			}
		}

	case FileSystemRecordTypeDirectoryEntry:
		// For directory entry records, compare hash and names
		return compareDirectoryEntryKeys(key1Data, key2Data)

	case FileSystemRecordTypeExtendedAttribute:
		// For extended attributes, compare names
		return compareExtendedAttributeKeys(key1Data, key2Data)
	}

	return 0
}

// ParseFileExtentValue parses a file extent value from binary data
func ParseFileExtentValue(data []byte) (*FileExtent, error) {
	// j_file_extent_val_t structure: len_and_flags (8) + phys_block_num (8) + crypto_id (8) = 24 bytes
	const fileExtentValueSize = 24

	if len(data) < fileExtentValueSize {
		return nil, fmt.Errorf("invalid file extent value size: expected at least %d bytes, got %d", fileExtentValueSize, len(data))
	}

	extent := &FileExtent{
		// Flags and size (8 bytes)
		// Physical block number (8 bytes)
		// Encryption identifier (8 bytes)
		// Logical offset is from the key, not the value
	}

	// Read flags and size (combined in first 8 bytes)
	flagsAndSize := binary.LittleEndian.Uint64(data[0:8])
	extent.DataSize = flagsAndSize & 0x00ffffffffffffff // Lower 56 bits

	// Read physical block number
	extent.PhysicalBlockNumber = binary.LittleEndian.Uint64(data[8:16])

	// Read encryption identifier
	extent.EncryptionIdentifier = binary.LittleEndian.Uint64(data[16:24])

	return extent, nil
}

// ParseFileExtentKey parses a file extent key from binary data
func ParseFileExtentKey(data []byte) (identifier uint64, logicalAddress uint64, err error) {
	const fileExtentKeySize = 16

	if len(data) < fileExtentKeySize {
		return 0, 0, fmt.Errorf("invalid file extent key size: expected at least %d bytes, got %d", fileExtentKeySize, len(data))
	}

	// Extract identifier from file system identifier
	fileSystemIdentifier := binary.LittleEndian.Uint64(data[0:8])
	identifier = fileSystemIdentifier & 0x0fffffffffffffff

	// Read logical address
	logicalAddress = binary.LittleEndian.Uint64(data[8:16])

	return identifier, logicalAddress, nil
}

// CreateFileSystemKey creates a file system B-tree key with identifier and data type
func CreateFileSystemKey(identifier uint64, dataType uint8) uint64 {
	// Combine identifier (lower 60 bits) with data type (upper 4 bits)
	return (identifier & 0x0fffffffffffffff) | (uint64(dataType) << 60)
}

// CreateFileExtentKey creates a file extent key
func CreateFileExtentKey(identifier uint64, logicalAddress uint64) []byte {
	key := make([]byte, 16)

	// Create file system identifier with data type
	fsid := CreateFileSystemKey(identifier, FileSystemRecordTypeFileExtent)
	binary.LittleEndian.PutUint64(key[0:8], fsid)

	// Add logical address
	binary.LittleEndian.PutUint64(key[8:16], logicalAddress)

	return key
}

// CreateInodeKey creates an inode key
func CreateInodeKey(identifier uint64) []byte {
	key := make([]byte, 8)

	// Create file system identifier with data type
	fsid := CreateFileSystemKey(identifier, FileSystemRecordTypeInode)
	binary.LittleEndian.PutUint64(key[0:8], fsid)

	return key
}

// compareDirectoryEntryKeys compares two directory entry record keys
// Returns <0 if key1 < key2, 0 if equal, >0 if key1 > key2
func compareDirectoryEntryKeys(key1Data []byte, key2Data []byte) int {
	// Minimum key size: 8 (fs_id) + 2 (name_size) = 10 bytes
	if len(key1Data) < 10 || len(key2Data) < 10 {
		return 0
	}

	// Check if keys contain hash (12+ bytes indicates hash variant)
	hasHash1 := len(key1Data) >= 12
	hasHash2 := len(key2Data) >= 12

	var nameHash1, nameHash2 uint32
	var nameOffset1, nameOffset2 int = 10, 10

	// Extract name size and hash if present
	if hasHash1 {
		nameSizeAndHash := binary.LittleEndian.Uint32(key1Data[8:12])
		nameHash1 = (nameSizeAndHash & 0xfffffc00) >> 10
		nameOffset1 = 12
	}

	if hasHash2 {
		nameSizeAndHash := binary.LittleEndian.Uint32(key2Data[8:12])
		nameHash2 = (nameSizeAndHash & 0xfffffc00) >> 10
		nameOffset2 = 12
	}

	// Compare hashes first if both are present
	if hasHash1 && hasHash2 && nameHash1 != 0 && nameHash2 != 0 {
		if nameHash1 < nameHash2 {
			return -1
		}
		if nameHash1 > nameHash2 {
			return 1
		}
	}

	// Compare names byte-by-byte
	name1 := key1Data[nameOffset1:]
	name2 := key2Data[nameOffset2:]

	minLen := len(name1)
	if len(name2) < minLen {
		minLen = len(name2)
	}

	for i := 0; i < minLen; i++ {
		if name1[i] < name2[i] {
			return -1
		}
		if name1[i] > name2[i] {
			return 1
		}
	}

	// If all compared bytes are equal, compare lengths
	if len(name1) < len(name2) {
		return -1
	}
	if len(name1) > len(name2) {
		return 1
	}

	return 0
}

// compareExtendedAttributeKeys compares two extended attribute keys
// Returns <0 if key1 < key2, 0 if equal, >0 if key1 > key2
func compareExtendedAttributeKeys(key1Data []byte, key2Data []byte) int {
	// Minimum key size: 8 (fs_id) + 2 (name_size) = 10 bytes
	if len(key1Data) < 10 || len(key2Data) < 10 {
		return 0
	}

	// Extract name sizes
	nameSize1 := binary.LittleEndian.Uint16(key1Data[8:10])
	nameSize2 := binary.LittleEndian.Uint16(key2Data[8:10])

	// Names start at offset 10
	nameOffset := 10

	// Get name slices
	var name1, name2 []byte
	if len(key1Data) > nameOffset && int(nameSize1) <= len(key1Data)-nameOffset {
		name1 = key1Data[nameOffset : nameOffset+int(nameSize1)]
	}
	if len(key2Data) > nameOffset && int(nameSize2) <= len(key2Data)-nameOffset {
		name2 = key2Data[nameOffset : nameOffset+int(nameSize2)]
	}

	// Compare names byte-by-byte
	minLen := len(name1)
	if len(name2) < minLen {
		minLen = len(name2)
	}

	for i := 0; i < minLen; i++ {
		if name1[i] < name2[i] {
			return -1
		}
		if name1[i] > name2[i] {
			return 1
		}
	}

	// If all compared bytes are equal, compare lengths
	if len(name1) < len(name2) {
		return -1
	}
	if len(name1) > len(name2) {
		return 1
	}

	return 0
}
