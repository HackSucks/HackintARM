package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Extended attribute flags
const (
	ExtendedAttributeFlagDataStream = 0x0001
	ExtendedAttributeFlagEmbedded   = 0x0002
)

// AttributeValues represents extended attribute values
type AttributeValues struct {
	// The flags
	Flags uint16

	// The name (UTF-8 encoded)
	Name []byte

	// The value data
	ValueData []byte

	// Value data size
	ValueDataSize uint64

	// Value data stream identifier
	ValueDataStreamIdentifier uint64

	// The value data file extents
	ValueDataFileExtents []*FileExtent
}

// NewAttributeValues creates a new AttributeValues instance
func NewAttributeValues() *AttributeValues {
	return &AttributeValues{
		ValueDataFileExtents: make([]*FileExtent, 0),
	}
}

// ReadKeyData reads the attribute values key data
func (av *AttributeValues) ReadKeyData(data []byte) error {
	if av.Name != nil {
		return fmt.Errorf("name value already set")
	}

	if len(data) < 10 { // Minimum size for FileSystemBTreeKeyExtendedAttribute
		return fmt.Errorf("invalid data size: %d", len(data))
	}

	// Read name size (2 bytes at offset 8)
	nameSize := binary.LittleEndian.Uint16(data[8:10])

	dataOffset := 10 // After file_system_identifier (8 bytes) and name_size (2 bytes)

	if nameSize == 0 || int(nameSize) > len(data)-dataOffset {
		return fmt.Errorf("invalid name size: %d", nameSize)
	}

	// Allocate and copy name
	av.Name = make([]byte, nameSize)
	copy(av.Name, data[dataOffset:dataOffset+int(nameSize)])

	return nil
}

// ReadValueData reads the attribute values value data
func (av *AttributeValues) ReadValueData(data []byte) error {
	if av.ValueData != nil {
		return fmt.Errorf("value data already set")
	}

	if len(data) < 4 { // Minimum size for FileSystemBTreeValueExtendedAttribute
		return fmt.Errorf("invalid data size: %d", len(data))
	}

	// Read flags (2 bytes)
	av.Flags = binary.LittleEndian.Uint16(data[0:2])

	// Debug output for extended attribute flags
	if DebugOutput {
		fmt.Printf("Extended attribute flags: 0x%04x\n", av.Flags)
		PrintExtendedAttributeFlags(av.Flags)
	}

	// Read data size (2 bytes)
	attributeValuesDataSize := binary.LittleEndian.Uint16(data[2:4])

	dataOffset := 4 // After flags and data_size

	if attributeValuesDataSize != 0 && int(attributeValuesDataSize) > len(data)-dataOffset {
		return fmt.Errorf("invalid attribute values data size: %d", attributeValuesDataSize)
	}

	if attributeValuesDataSize == 0 {
		return nil
	}

	attributeValuesData := data[dataOffset : dataOffset+int(attributeValuesDataSize)]

	// Check if this is a data stream reference
	if (av.Flags & ExtendedAttributeFlagDataStream) != 0 {
		if len(attributeValuesData) != 48 { // Size of FileSystemExtendedAttributeDataStream
			return fmt.Errorf("unsupported attribute values data size for data stream: %d", len(attributeValuesData))
		}

		// Read data stream identifier (8 bytes)
		av.ValueDataStreamIdentifier = binary.LittleEndian.Uint64(attributeValuesData[0:8])

		// Read used size (8 bytes)
		av.ValueDataSize = binary.LittleEndian.Uint64(attributeValuesData[8:16])

		// allocated_size, encryption_identifier, number_of_bytes_written, number_of_bytes_read
		// are at offsets 16, 24, 32, 40 respectively but not stored in this struct
	} else if (av.Flags & ExtendedAttributeFlagEmbedded) != 0 {
		// Embedded data - copy it
		if attributeValuesDataSize > 0 {
			av.ValueData = make([]byte, attributeValuesDataSize)
			copy(av.ValueData, attributeValuesData)
			av.ValueDataSize = uint64(attributeValuesDataSize)
		}
	}

	return nil
}

// Name returns the attribute name as a string
func (av *AttributeValues) NameString() string {
	// Remove null terminator if present
	name := bytes.TrimRight(av.Name, "\x00")
	return string(name)
}

// CompareName compares the attribute name with a given string
// Returns -1 if less, 0 if equal, 1 if greater
func (av *AttributeValues) CompareName(name string) int {
	return bytes.Compare(bytes.TrimRight(av.Name, "\x00"), []byte(name))
}

// NumberOfExtents returns the number of file extents
func (av *AttributeValues) NumberOfExtents() int {
	if av.ValueDataFileExtents == nil {
		return 0
	}
	return len(av.ValueDataFileExtents)
}

// ExtentByIndex retrieves a file extent by index
func (av *AttributeValues) ExtentByIndex(index int) (*FileExtent, error) {
	if av.ValueDataFileExtents == nil || index < 0 || index >= len(av.ValueDataFileExtents) {
		return nil, fmt.Errorf("invalid extent index: %d", index)
	}
	return av.ValueDataFileExtents[index], nil
}
