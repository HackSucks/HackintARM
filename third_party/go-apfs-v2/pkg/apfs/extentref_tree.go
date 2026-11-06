package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ExtentrefTree represents the APFS extentref tree structure
type ExtentrefTree struct {
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

	// Unknown
	// Consists of 4 bytes
	Unknown1 uint32
}

// Expected object type and subtype for extentref tree
const (
	ExtentrefTreeType                = 0x40000002
	ExtentReferenceTreeObjectSubtype = 0x0000000F
)

// NewExtentrefTree creates a new extentref tree
func NewExtentrefTree() *ExtentrefTree {
	return &ExtentrefTree{}
}

// ReadFrom reads the extentref tree from a file at a specific offset
func (ert *ExtentrefTree) ReadFrom(reader io.ReaderAt, fileOffset int64) error {
	if ert == nil {
		return fmt.Errorf("invalid extentref tree")
	}

	if DebugOutput {
		fmt.Printf("ExtentrefTree.ReadFrom: reading extentref tree at offset: %d (0x%08x)\n",
			fileOffset, fileOffset)
	}

	// Read extentref tree data (4096 bytes = one block)
	data := make([]byte, 4096)
	n, err := reader.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read extentref tree data at offset: %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}
	if n != 4096 {
		return fmt.Errorf("unable to read extentref tree data at offset: %d (0x%08x): read %d bytes, expected 4096",
			fileOffset, fileOffset, n)
	}

	// Parse the extentref tree data
	if err := ert.ReadData(data); err != nil {
		return fmt.Errorf("unable to read extentref tree data: %w", err)
	}

	return nil
}

// ReadData reads the extentref tree from data
func (ert *ExtentrefTree) ReadData(data []byte) error {
	if ert == nil {
		return fmt.Errorf("invalid extentref tree")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	// Minimum size check (40 bytes for the structure)
	const minSize = 40
	if len(data) < minSize {
		return fmt.Errorf("invalid data size value out of bounds: %d", len(data))
	}

	if DebugOutput {
		fmt.Printf("ExtentrefTree.ReadData: extentref tree data:\n")
		PrintData(data, true)
	}

	// Read object checksum (8 bytes at offset 0)
	ert.Checksum = binary.LittleEndian.Uint64(data[0:8])

	// Read object identifier (8 bytes at offset 8)
	ert.OID = binary.LittleEndian.Uint64(data[8:16])

	// Read object transaction identifier (8 bytes at offset 16)
	ert.XID = binary.LittleEndian.Uint64(data[16:24])

	// Read object type (4 bytes at offset 24)
	ert.ObjectType = binary.LittleEndian.Uint32(data[24:28])

	// Read object subtype (4 bytes at offset 28)
	ert.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	// Read unknown1 (4 bytes at offset 32)
	ert.Unknown1 = binary.LittleEndian.Uint32(data[32:36])

	// Validate object type
	if ert.ObjectType != ExtentrefTreeType {
		return fmt.Errorf("invalid object type: 0x%08x", ert.ObjectType)
	}

	// Validate object subtype
	if ert.ObjectSubtype != ExtentReferenceTreeObjectSubtype {
		return fmt.Errorf("invalid object subtype: 0x%08x", ert.ObjectSubtype)
	}

	if DebugOutput {
		fmt.Printf("ExtentrefTree.ReadData: object checksum\t\t\t: 0x%08x\n", ert.Checksum)
		fmt.Printf("ExtentrefTree.ReadData: object identifier\t\t\t: %d\n", ert.OID)
		fmt.Printf("ExtentrefTree.ReadData: object transaction identifier\t: %d\n", ert.XID)
		fmt.Printf("ExtentrefTree.ReadData: object type\t\t\t\t: 0x%08x\n", ert.ObjectType)
		fmt.Printf("ExtentrefTree.ReadData: object subtype\t\t\t: 0x%08x\n", ert.ObjectSubtype)
		fmt.Printf("ExtentrefTree.ReadData: unknown1\t\t\t\t: 0x%08x\n", ert.Unknown1)
		fmt.Println()
	}

	return nil
}
