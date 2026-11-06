package apfs

import (
	"encoding/binary"
	"fmt"
)

// FileExtent represents a file extent structure
type FileExtent struct {
	// The logical offset
	LogicalOffset uint64

	// The physical block number
	PhysicalBlockNumber uint64

	// Data size
	DataSize uint64

	// Encryption identifier
	EncryptionIdentifier uint64
}

// NewFileExtent creates a new file extent
func NewFileExtent() *FileExtent {
	return &FileExtent{}
}

// ReadKeyData reads the file extent key data
func (fe *FileExtent) ReadKeyData(data []byte) error {
	if fe == nil {
		return fmt.Errorf("invalid file extent")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	// FileSystemBTreeKeyFileExtent is 16 bytes minimum
	const minKeySize = 16
	if len(data) < minKeySize {
		return fmt.Errorf("invalid data size for file extent key: %d", len(data))
	}

	if DebugOutput {
		fmt.Printf("FileExtent.ReadKeyData: file extent key data:\n")
		PrintData(data, true)
	}

	// Read file system identifier (8 bytes at offset 0) - contains identifier and type
	fileSystemIdentifier := binary.LittleEndian.Uint64(data[0:8])

	// Read logical address (8 bytes at offset 8)
	fe.LogicalOffset = binary.LittleEndian.Uint64(data[8:16])

	if DebugOutput {
		fmt.Printf("FileExtent.ReadKeyData: identifier\t\t\t\t: 0x%08x\n", fileSystemIdentifier)
		fmt.Printf("FileExtent.ReadKeyData: logical address\t\t\t: 0x%08x\n", fe.LogicalOffset)
		fmt.Println()
	}

	return nil
}

// ReadValueData reads the file extent value data
func (fe *FileExtent) ReadValueData(data []byte) error {
	if fe == nil {
		return fmt.Errorf("invalid file extent")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	// FileSystemBTreeValueFileExtent is 24 bytes minimum
	const minValueSize = 24
	if len(data) < minValueSize {
		return fmt.Errorf("invalid data size for file extent value: %d", len(data))
	}

	if DebugOutput {
		fmt.Printf("FileExtent.ReadValueData: file extent value data:\n")
		PrintData(data, true)
	}

	// Read data size and flags (8 bytes at offset 0)
	dataSizeAndFlags := binary.LittleEndian.Uint64(data[0:8])
	fe.DataSize = dataSizeAndFlags & 0x00FFFFFFFFFFFFFF // Lower 56 bits (mask out upper 8 bits)

	// Read physical block number (8 bytes at offset 8)
	fe.PhysicalBlockNumber = binary.LittleEndian.Uint64(data[8:16])

	// Read encryption identifier (8 bytes at offset 16)
	fe.EncryptionIdentifier = binary.LittleEndian.Uint64(data[16:24])

	if DebugOutput {
		flags := dataSizeAndFlags >> 56
		fmt.Printf("FileExtent.ReadValueData: data size and flags\t\t: 0x%08x (data size: %d, flags: 0x%02x)\n",
			dataSizeAndFlags, fe.DataSize, flags)
		fmt.Printf("FileExtent.ReadValueData: physical block number\t\t: %d\n", fe.PhysicalBlockNumber)
		fmt.Printf("FileExtent.ReadValueData: encryption identifier\t\t: %d\n", fe.EncryptionIdentifier)
		fmt.Println()
	}

	return nil
}
