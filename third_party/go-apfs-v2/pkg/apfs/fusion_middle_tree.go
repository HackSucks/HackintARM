// The APFS Fusion middle tree definition
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// FusionMiddleTreeSize is the size of the Fusion middle tree structure in bytes
const FusionMiddleTreeSize = 40

// FusionMiddleTree represents the APFS Fusion middle tree structure
type FusionMiddleTree struct {
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

// NewFusionMiddleTree creates a new Fusion middle tree
func NewFusionMiddleTree() (*FusionMiddleTree, error) {
	return &FusionMiddleTree{}, nil
}

// ReadFrom reads the Fusion middle tree from a file at the specified offset
func (f *FusionMiddleTree) ReadFrom(reader io.ReaderAt, fileOffset int64) error {
	if f == nil {
		return fmt.Errorf("invalid Fusion middle tree")
	}

	// Allocate 4096 bytes for Fusion middle tree data (standard APFS block)
	fusionMiddleTreeData := make([]byte, 4096)

	// Read data from file
	n, err := reader.ReadAt(fusionMiddleTreeData, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read Fusion middle tree data at offset %d (0x%08x): %w", fileOffset, fileOffset, err)
	}

	if n != 4096 {
		return fmt.Errorf("unable to read Fusion middle tree data at offset %d (0x%08x)", fileOffset, fileOffset)
	}

	// Parse the data
	if err := f.ReadData(fusionMiddleTreeData); err != nil {
		return fmt.Errorf("unable to read Fusion middle tree data: %w", err)
	}

	return nil
}

// ReadData reads the Fusion middle tree from binary data
func (f *FusionMiddleTree) ReadData(data []byte) error {
	if f == nil {
		return fmt.Errorf("invalid Fusion middle tree")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < FusionMiddleTreeSize || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	// Read Fusion middle tree fields
	f.Checksum = binary.LittleEndian.Uint64(data[0:8])
	f.OID = binary.LittleEndian.Uint64(data[8:16])
	f.XID = binary.LittleEndian.Uint64(data[16:24])
	f.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	f.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])
	f.Unknown1 = binary.LittleEndian.Uint32(data[32:36])

	// Validate object type
	if f.ObjectType != 0x40000002 {
		return fmt.Errorf("invalid object type: 0x%08x", f.ObjectType)
	}

	// Validate object subtype
	if f.ObjectSubtype != 0x00000015 {
		return fmt.Errorf("invalid object subtype: 0x%08x", f.ObjectSubtype)
	}

	// Debug output
	if isVerbose() {
		notifyPrintf("Fusion middle tree data:\n")
		PrintData(data, true)

		notifyPrintf("object checksum\t\t\t: 0x%08x\n", f.Checksum)
		notifyPrintf("object identifier\t\t: %d\n", f.OID)
		notifyPrintf("object transaction identifier\t: %d\n", f.XID)
		notifyPrintf("object type\t\t\t: 0x%08x\n", f.ObjectType)
		notifyPrintf("object subtype\t\t\t: 0x%08x\n", f.ObjectSubtype)
		notifyPrintf("unknown1\t\t\t: 0x%08x\n", f.Unknown1)
		notifyPrintf("\n")
	}

	return nil
}
