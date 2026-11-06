package apfs

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// DirectoryEntryRecord represents an APFS directory entry record (directory entry)
type DirectoryEntryRecord struct {
	// Identifier (inode number of the directory entry)
	Identifier uint64

	// ParentIdentifier (from the key)
	ParentIdentifier uint64

	// NameSize is the size of the name in bytes
	NameSize uint16

	// Name is the UTF-8 encoded name
	Name []byte

	// NameHash is the optional name hash (if present in key)
	NameHash uint32

	// AddedTime is the time when entry was added (nanoseconds since Unix epoch)
	AddedTime uint64

	// Flags are the directory entry flags
	Flags uint16

	// ExtendedFields stores any parsed extended fields
	ExtendedFields []ExtendedField
}

// ExtendedField represents an extended field in a directory entry record
type ExtendedField struct {
	Type  uint8
	Flags uint8
	Data  []byte
}

// DirectoryRecordExtendedFieldType constants
const (
	DirectoryEntryExtendedFieldTypeSiblingID = 1
)

// NewDirectoryEntryRecord creates a new directory entry record
func NewDirectoryEntryRecord() *DirectoryEntryRecord {
	return &DirectoryEntryRecord{}
}

// ReadKeyData reads the directory entry record key data from a B-tree entry
func (dr *DirectoryEntryRecord) ReadKeyData(data []byte) error {
	if dr == nil {
		return fmt.Errorf("invalid directory entry record")
	}

	if dr.Name != nil {
		return fmt.Errorf("name value already set")
	}

	// Minimum size is FileSystemBTreeKeyDirectoryRecord (8 + 2 = 10 bytes)
	const minKeySize = 10

	if len(data) < minKeySize {
		return fmt.Errorf("invalid key data size: expected at least %d bytes, got %d", minKeySize, len(data))
	}

	// Read parent identifier (lower 60 bits)
	fileSystemIdentifier := binary.LittleEndian.Uint64(data[0:8])
	dr.ParentIdentifier = fileSystemIdentifier & 0x0fffffffffffffff

	// Read name size field (lower 10 bits)
	nameSizeField := binary.LittleEndian.Uint16(data[8:10])
	nameSize := uint32(nameSizeField) & 0x000003ff

	dataOffset := 10

	// Determine if this key contains a hash
	// If there's more data than just the name, it might be a hash variant
	if int(nameSize) < (len(data) - dataOffset) {
		// This is a directory entry record with hash
		if len(data) < 12 {
			return fmt.Errorf("invalid key data size for hash variant: expected at least 12 bytes, got %d", len(data))
		}

		// Read name size and hash (combined in 32 bits)
		nameSizeAndHash := binary.LittleEndian.Uint32(data[8:12])
		nameSize = nameSizeAndHash & 0x000003ff
		dr.NameHash = (nameSizeAndHash & 0xfffffc00) >> 10

		dataOffset = 12
	}

	// Validate name size
	if nameSize == 0 || int(nameSize) > (len(data)-dataOffset) {
		return fmt.Errorf("invalid name size: %d (available: %d)", nameSize, len(data)-dataOffset)
	}

	// Copy name data
	dr.Name = make([]byte, nameSize)
	copy(dr.Name, data[dataOffset:dataOffset+int(nameSize)])

	// Strip null terminator if present
	if len(dr.Name) > 0 && dr.Name[len(dr.Name)-1] == 0 {
		dr.Name = dr.Name[:len(dr.Name)-1]
	}

	dr.NameSize = uint16(nameSize)

	return nil
}

// ReadValueData reads the directory entry record value data from a B-tree entry
func (dr *DirectoryEntryRecord) ReadValueData(data []byte) error {
	if dr == nil {
		return fmt.Errorf("invalid directory entry record")
	}

	// Minimum size is FileSystemBTreeValueDirectoryRecord (8 + 8 + 2 = 18 bytes)
	const minValueSize = 18

	if len(data) < minValueSize {
		return fmt.Errorf("invalid value data size: expected at least %d bytes, got %d", minValueSize, len(data))
	}

	// Read fixed fields
	dr.Identifier = binary.LittleEndian.Uint64(data[0:8])
	dr.AddedTime = binary.LittleEndian.Uint64(data[8:16])
	dr.Flags = binary.LittleEndian.Uint16(data[16:18])

	// Debug output
	if DebugOutput {
		fmt.Printf("DirectoryEntryRecord.ReadValueData: directory entry record value data:\n")
		PrintData(data, true)

		fmt.Printf("DirectoryEntryRecord.ReadValueData: identifier\t\t\t\t: %d\n", dr.Identifier)

		timeBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(timeBytes, dr.AddedTime)
		if err := PrintPOSIXTimeValue("DirectoryEntryRecord.ReadValueData", "added time", timeBytes, binary.LittleEndian, "nanoseconds"); err != nil {
			fmt.Printf("Warning: unable to print added time: %v\n", err)
		}

		fmt.Printf("DirectoryEntryRecord.ReadValueData: directory entry flags\t\t: 0x%04x\n", dr.Flags)
		PrintDirectoryEntryFlags(dr.Flags)
		fmt.Printf("\n")
	}

	// Parse extended fields if present
	if len(data) > minValueSize {
		if err := dr.parseExtendedFields(data[minValueSize:]); err != nil {
			return fmt.Errorf("failed to parse extended fields: %w", err)
		}
	}

	return nil
}

// parseExtendedFields parses the extended fields from directory entry record value data
func (dr *DirectoryEntryRecord) parseExtendedFields(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("insufficient data for extended fields header")
	}

	dataOffset := 0
	numberOfExtendedFields := binary.LittleEndian.Uint16(data[dataOffset : dataOffset+2])

	if DebugOutput {
		fmt.Printf("DirectoryEntryRecord.ReadValueData: number of extended fields\t\t: %d\n", numberOfExtendedFields)
		unknown1 := binary.LittleEndian.Uint16(data[dataOffset+2 : dataOffset+4])
		fmt.Printf("DirectoryEntryRecord.ReadValueData: unknown1\t\t\t\t: 0x%04x\n", unknown1)
	}

	dataOffset += 4
	valueDataOffset := dataOffset + (int(numberOfExtendedFields) * 4)

	if valueDataOffset > len(data) {
		return fmt.Errorf("invalid extended fields: offset out of bounds")
	}

	dr.ExtendedFields = make([]ExtendedField, 0, numberOfExtendedFields)

	for fieldIndex := uint16(0); fieldIndex < numberOfExtendedFields; fieldIndex++ {
		if dataOffset+4 > len(data) {
			return fmt.Errorf("invalid extended field header at index %d", fieldIndex)
		}

		fieldType := data[dataOffset]
		fieldFlags := data[dataOffset+1]
		valueDataSize := binary.LittleEndian.Uint16(data[dataOffset+2 : dataOffset+4])

		if DebugOutput {
			fmt.Printf("DirectoryEntryRecord.ReadValueData: extended field: %d type\t\t: %d %s\n",
				fieldIndex, fieldType, DirectoryEntryExtendedFieldTypeName(fieldType))
			fmt.Printf("DirectoryEntryRecord.ReadValueData: extended field: %d flags\t\t: 0x%02x\n",
				fieldIndex, fieldFlags)
			PrintExtendedFieldFlags(fieldFlags)
			fmt.Printf("\n")
			fmt.Printf("DirectoryEntryRecord.ReadValueData: extended field: %d value data size\t: %d\n",
				fieldIndex, valueDataSize)
		}

		dataOffset += 4

		if valueDataOffset+int(valueDataSize) > len(data) {
			return fmt.Errorf("invalid extended field value data at index %d", fieldIndex)
		}

		valueData := make([]byte, valueDataSize)
		copy(valueData, data[valueDataOffset:valueDataOffset+int(valueDataSize)])

		if DebugOutput && valueDataSize > 0 {
			fmt.Printf("DirectoryEntryRecord.ReadValueData: extended field: %d value data:\n", fieldIndex)
			PrintData(valueData, false)
		}

		// Validate supported field types
		switch fieldType {
		case DirectoryEntryExtendedFieldTypeSiblingID:
			// Valid field type
		default:
			return fmt.Errorf("unsupported extended field type: %d", fieldType)
		}

		dr.ExtendedFields = append(dr.ExtendedFields, ExtendedField{
			Type:  fieldType,
			Flags: fieldFlags,
			Data:  valueData,
		})

		valueDataOffset += int(valueDataSize)

		// Handle trailing padding (aligned to 8 bytes)
		trailingDataSize := int(valueDataSize) % 8
		if trailingDataSize > 0 {
			trailingDataSize = 8 - trailingDataSize
			if valueDataOffset+trailingDataSize > len(data) {
				trailingDataSize = len(data) - valueDataOffset
			}

			if DebugOutput && trailingDataSize > 0 {
				fmt.Printf("DirectoryEntryRecord.ReadValueData: extended field: %d trailing data:\n", fieldIndex)
				PrintData(data[valueDataOffset:valueDataOffset+trailingDataSize], false)
			}

			valueDataOffset += trailingDataSize
		}
	}

	if DebugOutput {
		fmt.Printf("\n")
	}

	return nil
}

// Clone creates a deep copy of the directory entry record
func (dr *DirectoryEntryRecord) Clone() (*DirectoryEntryRecord, error) {
	if dr == nil {
		return nil, nil
	}

	clone := &DirectoryEntryRecord{
		Identifier:       dr.Identifier,
		ParentIdentifier: dr.ParentIdentifier,
		NameSize:         dr.NameSize,
		NameHash:         dr.NameHash,
		AddedTime:        dr.AddedTime,
		Flags:            dr.Flags,
	}

	if dr.Name != nil {
		clone.Name = make([]byte, len(dr.Name))
		copy(clone.Name, dr.Name)
	}

	if dr.ExtendedFields != nil {
		clone.ExtendedFields = make([]ExtendedField, len(dr.ExtendedFields))
		for i, field := range dr.ExtendedFields {
			clone.ExtendedFields[i] = ExtendedField{
				Type:  field.Type,
				Flags: field.Flags,
			}
			if field.Data != nil {
				clone.ExtendedFields[i].Data = make([]byte, len(field.Data))
				copy(clone.ExtendedFields[i].Data, field.Data)
			}
		}
	}

	return clone, nil
}

// UTF8NameSize retrieves the size of the UTF-8 encoded name
// The returned size includes the end-of-string character
func (dr *DirectoryEntryRecord) UTF8NameSize() (int, error) {
	if dr == nil {
		return 0, fmt.Errorf("invalid directory entry record")
	}
	// Return size + 1 for null terminator to match C API behavior
	return len(dr.Name) + 1, nil
}

// UTF8Name retrieves the UTF-8 encoded name
func (dr *DirectoryEntryRecord) UTF8Name() (string, error) {
	if dr == nil {
		return "", fmt.Errorf("invalid directory entry record")
	}
	if dr.Name == nil {
		return "", nil
	}
	return string(dr.Name), nil
}

// UTF16NameSize retrieves the size of the UTF-16 encoded name
// The returned size includes the end-of-string character
func (dr *DirectoryEntryRecord) UTF16NameSize() (int, error) {
	if dr == nil {
		return 0, fmt.Errorf("invalid directory entry record")
	}

	// Count the UTF-16 code units needed
	utf16Count := 0
	nameBytes := dr.Name
	for len(nameBytes) > 0 {
		r, size := utf8.DecodeRune(nameBytes)
		if r == utf8.RuneError {
			return 0, fmt.Errorf("invalid UTF-8 sequence")
		}
		if r <= 0xFFFF {
			utf16Count++
		} else {
			utf16Count += 2 // Surrogate pair
		}
		nameBytes = nameBytes[size:]
	}

	// Add 1 for null terminator
	return utf16Count + 1, nil
}

// UTF16Name retrieves the UTF-16 encoded name
func (dr *DirectoryEntryRecord) UTF16Name() ([]uint16, error) {
	if dr == nil {
		return nil, fmt.Errorf("invalid directory entry record")
	}
	if dr.Name == nil {
		return nil, nil
	}

	// Convert UTF-8 to UTF-16
	runes := []rune(string(dr.Name))
	utf16Encoded := utf16.Encode(runes)

	return utf16Encoded, nil
}

// CompareNameWithUTF8String compares an UTF-8 string with a directory entry record name
// Returns -1 if less, 0 if equal, 1 if greater
func (dr *DirectoryEntryRecord) CompareNameWithUTF8String(utf8String []byte, nameHash uint32, useCaseFolding bool) int {
	if dr == nil {
		return -1
	}

	// Compare name hash first if both are available
	if dr.NameHash != 0 && nameHash != 0 {
		if nameHash < dr.NameHash {
			return -1
		}
		if nameHash > dr.NameHash {
			return 1
		}
	}

	// Compare names
	if dr.Name != nil {
		return compareNamesWithUTF8(dr.Name, utf8String, useCaseFolding)
	}

	return 0
}

// CompareNameWithUTF16String compares an UTF-16 string with a directory entry record name
// Returns -1 if less, 0 if equal, 1 if greater
func (dr *DirectoryEntryRecord) CompareNameWithUTF16String(utf16String []uint16, nameHash uint32, useCaseFolding bool) int {
	if dr == nil {
		return -1
	}

	// Compare name hash first if both are available
	if dr.NameHash != 0 && nameHash != 0 {
		if nameHash < dr.NameHash {
			return -1
		}
		if nameHash > dr.NameHash {
			return 1
		}
	}

	// Compare names
	if dr.Name != nil {
		// Convert UTF-16 to UTF-8 for comparison
		runes := utf16.Decode(utf16String)
		utf8Bytes := []byte(string(runes))
		return compareNamesWithUTF8(dr.Name, utf8Bytes, useCaseFolding)
	}

	return 0
}

// Name returns the name as a string (convenience method)
func (dr *DirectoryEntryRecord) NameString() string {
	if dr == nil || dr.Name == nil {
		return ""
	}
	return string(dr.Name)
}

// IsDirectory returns true if this record represents a directory
func (dr *DirectoryEntryRecord) IsDirectory() bool {
	// Flag 0x0001 indicates a directory
	return (dr.Flags & 0x0001) != 0
}

// CompareName compares the directory entry record name with the given name (convenience method)
// Returns 0 if equal, <0 if dr.Name < name, >0 if dr.Name > name
func (dr *DirectoryEntryRecord) CompareName(name []byte, nameHash uint32, useCaseFolding bool) int {
	return dr.CompareNameWithUTF8String(name, nameHash, useCaseFolding)
}

// compareNamesWithUTF8 compares two UTF-8 encoded names
// Uses the proper Unicode normalization and case folding implementation from name_hash.go
func compareNamesWithUTF8(name1, name2 []byte, useCaseFolding bool) int {
	// Use the full Unicode-aware comparison from name_hash.go
	// This provides proper NFD normalization and case folding as per the C library
	return CompareNamesWithUTF8(name1, name2, useCaseFolding)
}
