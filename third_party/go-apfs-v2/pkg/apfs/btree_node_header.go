package apfs

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// BTreeNodeHeaderSize is the size of the B-tree node header in bytes
const BTreeNodeHeaderSize = 24

// NewBTreeNodeHeader creates a new B-tree node header
func NewBTreeNodeHeader() *BTreeNodeHeader {
	return &BTreeNodeHeader{}
}

// ReadData reads the B-tree node header from binary data
func (h *BTreeNodeHeader) ReadData(data []byte) error {
	if h == nil {
		return fmt.Errorf("invalid B-tree node header")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < BTreeNodeHeaderSize || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	// Read fields using little-endian byte order
	h.Flags = binary.LittleEndian.Uint16(data[0:2])
	h.Level = binary.LittleEndian.Uint16(data[2:4])
	h.NumberOfKeys = binary.LittleEndian.Uint32(data[4:8])

	// Debug output for B-tree node flags
	if DebugOutput {
		fmt.Printf("B-tree node flags: 0x%04x\n", h.Flags)
		PrintBTreeNodeFlags(h.Flags)
	}
	h.EntriesDataOffset = binary.LittleEndian.Uint16(data[8:10])
	h.EntriesDataSize = binary.LittleEndian.Uint16(data[10:12])
	h.UnusedDataOffset = binary.LittleEndian.Uint16(data[12:14])
	h.UnusedDataSize = binary.LittleEndian.Uint16(data[14:16])
	h.KeyFreeListOffset = binary.LittleEndian.Uint16(data[16:18])
	h.KeyFreeListSize = binary.LittleEndian.Uint16(data[18:20])
	h.ValueFreeListOffset = binary.LittleEndian.Uint16(data[20:22])
	h.ValueFreeListSize = binary.LittleEndian.Uint16(data[22:24])

	return nil
}

// IsRoot returns true if this is a root node
func (h *BTreeNodeHeader) IsRoot() bool {
	return (h.Flags & 0x0001) != 0
}

// IsLeaf returns true if this is a leaf node
func (h *BTreeNodeHeader) IsLeaf() bool {
	return (h.Flags & 0x0002) != 0
}

// HasFixedKVSize returns true if keys and values are fixed size
// Corresponds to BTNODE_FIXED_KV_SIZE flag (0x0004)
func (h *BTreeNodeHeader) HasFixedKVSize() bool {
	return (h.Flags & 0x0004) != 0
}

// HasFixedSizeKeys returns true if keys are fixed size
func (h *BTreeNodeHeader) HasFixedSizeKeys() bool {
	return (h.Flags & 0x0004) != 0
}

// HasFixedSizeValues returns true if values are fixed size
func (h *BTreeNodeHeader) HasFixedSizeValues() bool {
	return (h.Flags & 0x0008) != 0
}
