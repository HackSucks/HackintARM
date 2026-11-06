package apfs

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// BTreeInfoSize is the size of the B-tree info in bytes
const BTreeInfoSize = 40

// NewBTreeInfo creates a new B-tree info
func NewBTreeInfo() *BTreeInfo {
	return &BTreeInfo{}
}

// ReadData reads the B-tree info from binary data
func (f *BTreeInfo) ReadData(data []byte) error {
	if f == nil {
		return fmt.Errorf("invalid B-tree info")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < BTreeInfoSize || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	// Read fields using little-endian byte order
	f.Flags = binary.LittleEndian.Uint32(data[0:4])

	// Debug output for B-tree flags
	if DebugOutput {
		fmt.Printf("B-tree flags: 0x%08x\n", f.Flags)
		PrintBTreeFlags(f.Flags)
	}

	f.NodeSize = binary.LittleEndian.Uint32(data[4:8])
	f.KeySize = binary.LittleEndian.Uint32(data[8:12])
	f.ValueSize = binary.LittleEndian.Uint32(data[12:16])
	f.MaximumKeySize = binary.LittleEndian.Uint32(data[16:20])
	f.MaximumValueSize = binary.LittleEndian.Uint32(data[20:24])
	f.TotalNumberOfKeys = binary.LittleEndian.Uint64(data[24:32])
	f.TotalNumberOfNodes = binary.LittleEndian.Uint64(data[32:40])

	return nil
}

// HasFixedSizeKeys returns true if keys are fixed size
func (f *BTreeInfo) HasFixedSizeKeys() bool {
	return (f.Flags & 0x00000001) != 0
}

// HasFixedSizeValues returns true if values are fixed size
func (f *BTreeInfo) HasFixedSizeValues() bool {
	return (f.Flags & 0x00000002) != 0
}

// UsesHashes returns true if the B-tree uses hashes
func (f *BTreeInfo) UsesHashes() bool {
	return (f.Flags & 0x00000004) != 0
}
