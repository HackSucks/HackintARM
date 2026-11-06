// The APFS checkpoint map definition
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// CheckpointMapSize is the size of the checkpoint map header in bytes
const CheckpointMapSize = 40

// CheckpointMap represents the APFS checkpoint map structure
type CheckpointMap struct {
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

	// The flags
	// Consists of 4 bytes
	Flags uint32

	// The number of entries
	// Consists of 4 bytes
	NumberOfEntries uint32

	// The entries array
	// Consists of 101 x 40 bytes
	EntriesArray [4040]byte

	// Parsed entries
	Entries []*CheckpointMapping
}

// CheckpointMapping represents the APFS checkpoint map entry structure
type CheckpointMapping struct {
	// The object type
	// Consists of 4 bytes
	ObjectType uint32

	// The object subtype
	// Consists of 4 bytes
	ObjectSubtype uint32

	// The size
	// Consists of 4 bytes
	Size uint32

	// Unknown
	// Consists of 4 bytes
	Unknown1 uint32

	// The file system object identifier
	// Consists of 8 bytes
	FileSystemObjectIdentifier uint64

	// The object identifier
	// Consists of 8 bytes
	OID uint64

	// The physical address
	// Consists of 8 bytes
	PhysicalAddress uint64
}

// NewCheckpointMap creates a new checkpoint map
func NewCheckpointMap() *CheckpointMap {
	return &CheckpointMap{
		Entries: make([]*CheckpointMapping, 0),
	}
}

// ReadFrom reads the checkpoint map from a file handle at the specified offset
func (cm *CheckpointMap) ReadFrom(reader io.ReaderAt, fileOffset int64) error {
	if cm == nil {
		return fmt.Errorf("invalid checkpoint map")
	}

	// Allocate 4096 bytes for checkpoint map data
	checkpointMapData := make([]byte, 4096)

	// Read data from file
	n, err := reader.ReadAt(checkpointMapData, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read checkpoint map data at offset %d: %w", fileOffset, err)
	}

	if n != 4096 {
		return fmt.Errorf("unable to read complete checkpoint map data: expected 4096 bytes, got %d", n)
	}

	// Parse the data
	if err := cm.ReadData(checkpointMapData); err != nil {
		return fmt.Errorf("unable to read checkpoint map data: %w", err)
	}

	return nil
}

// ReadData reads the checkpoint map from binary data
func (cm *CheckpointMap) ReadData(data []byte) error {
	if cm == nil {
		return fmt.Errorf("invalid checkpoint map")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < CheckpointMapSize || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	// Read checkpoint map header fields
	cm.Checksum = binary.LittleEndian.Uint64(data[0:8])
	cm.OID = binary.LittleEndian.Uint64(data[8:16])
	cm.XID = binary.LittleEndian.Uint64(data[16:24])
	cm.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	cm.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])
	cm.Flags = binary.LittleEndian.Uint32(data[32:36])

	// Debug output for checkpoint flags
	if DebugOutput {
		fmt.Printf("Checkpoint flags: 0x%08x\n", cm.Flags)
		PrintCheckpointFlags(cm.Flags)
	}

	cm.NumberOfEntries = binary.LittleEndian.Uint32(data[36:40])

	// Validate object type and subtype
	if cm.ObjectType != 0x4000000c {
		return fmt.Errorf("invalid object type: 0x%08x", cm.ObjectType)
	}

	if cm.ObjectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", cm.ObjectSubtype)
	}

	// Validate number of entries
	if cm.NumberOfEntries > 101 {
		return fmt.Errorf("invalid number of entries: %d > 101", cm.NumberOfEntries)
	}

	// Copy entries array data
	copy(cm.EntriesArray[:], data[40:])

	// Parse entries
	cm.Entries = make([]*CheckpointMapping, 0, cm.NumberOfEntries)
	dataOffset := 40

	for i := uint32(0); i < cm.NumberOfEntries; i++ {
		entry := NewCheckpointMapping()

		entryData := data[dataOffset : dataOffset+CheckpointMappingSize]
		if err := entry.ReadData(entryData); err != nil {
			return fmt.Errorf("unable to read checkpoint map entry %d: %w", i, err)
		}

		cm.Entries = append(cm.Entries, entry)
		dataOffset += CheckpointMappingSize
	}

	return nil
}

// PhysicalAddressByObjectIdentifier retrieves the physical address for a specific object identifier
// Returns the physical address and a boolean indicating if found
func (cm *CheckpointMap) PhysicalAddressByObjectIdentifier(oid uint64) (uint64, error) {
	if cm == nil {
		return 0, fmt.Errorf("invalid checkpoint map")
	}

	// Search through entries
	for _, entry := range cm.Entries {
		if entry.OID == oid {
			return entry.PhysicalAddress, nil
		}
	}

	return 0, fmt.Errorf("object identifier not found: %d", oid)
}
