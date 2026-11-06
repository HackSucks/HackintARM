package apfs

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// CheckpointMappingSize is the size of the checkpoint map entry in bytes
const CheckpointMappingSize = 40

// NewCheckpointMapping creates a new checkpoint map entry
func NewCheckpointMapping() *CheckpointMapping {
	return &CheckpointMapping{}
}

// ReadData reads the checkpoint map entry from binary data
func (cme *CheckpointMapping) ReadData(data []byte) error {
	if cme == nil {
		return fmt.Errorf("invalid checkpoint map entry")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < CheckpointMappingSize || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	// Read fields using little-endian byte order
	cme.ObjectType = binary.LittleEndian.Uint32(data[0:4])
	cme.ObjectSubtype = binary.LittleEndian.Uint32(data[4:8])
	cme.Size = binary.LittleEndian.Uint32(data[8:12])
	cme.Unknown1 = binary.LittleEndian.Uint32(data[12:16])
	cme.FileSystemObjectIdentifier = binary.LittleEndian.Uint64(data[16:24])
	cme.OID = binary.LittleEndian.Uint64(data[24:32])
	cme.PhysicalAddress = binary.LittleEndian.Uint64(data[32:40])

	return nil
}
