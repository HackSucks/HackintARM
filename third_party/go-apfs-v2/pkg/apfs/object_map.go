// The APFS object map definitions
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// ObjectMap represents the APFS object map structure
type ObjectMap struct {
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

	// The number of snapshots
	// Consists of 4 bytes
	SnapshotCount uint32

	// The B-tree type
	// Consists of 4 bytes
	TreeType uint32

	// The snapshots B-tree type
	// Consists of 4 bytes
	SnapshotTreeType uint32

	// The B-tree block number
	// Consists of 8 bytes
	TreeOID uint64

	// The snapshots B-tree block number
	// Consists of 8 bytes
	SnapshotTreeOID uint64

	// The most recent snapshot object identifier
	// Consists of 8 bytes
	MostRecentSnapXID uint64

	// Unknown
	// Consists of 8 bytes
	Unknown2 uint64

	// Unknown
	// Consists of 8 bytes
	Unknown3 uint64
}

// ObjectMapSize is the size of an object map in bytes
const ObjectMapSize = 104

// ObjectMapObjectType is the object type for an object map
const ObjectMapObjectType = 0x4000000b

// NewObjectMap creates a new object map
func NewObjectMap() (*ObjectMap, error) {
	return &ObjectMap{}, nil
}

// ReadFrom reads the object map from a file at the specified offset
func (om *ObjectMap) ReadFrom(reader io.ReaderAt, fileOffset int64) error {
	if om == nil {
		return fmt.Errorf("invalid object map")
	}

	if isVerbose() {
		notifyPrintf("%s: reading object map at offset: %d (0x%08x)\n",
			"ReadFrom", fileOffset, fileOffset)
	}

	// Read object map data (104 bytes)
	data := make([]byte, ObjectMapSize)
	n, err := reader.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read object map data at offset %d (0x%08x): %w", fileOffset, fileOffset, err)
	}
	if n != ObjectMapSize {
		return fmt.Errorf("unable to read object map data at offset %d (0x%08x)", fileOffset, fileOffset)
	}

	if err := om.ReadData(data); err != nil {
		return fmt.Errorf("unable to read object map data: %w", err)
	}

	return nil
}

// ReadData reads the object map from binary data
func (om *ObjectMap) ReadData(data []byte) error {
	if om == nil {
		return fmt.Errorf("invalid object map")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < ObjectMapSize || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	if isVerbose() {
		notifyPrintf("%s: object map data:\n", "ReadData")
		PrintData(data[:ObjectMapSize], true)
	}

	// Parse object type and subtype first for validation
	om.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	om.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	// Validate object type
	if om.ObjectType != ObjectMapObjectType {
		return fmt.Errorf("invalid object type: 0x%08x", om.ObjectType)
	}

	// Validate object subtype
	if om.ObjectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", om.ObjectSubtype)
	}

	// Parse the fields we actually use (from C implementation)
	om.SnapshotCount = binary.LittleEndian.Uint32(data[36:40])
	om.TreeOID = binary.LittleEndian.Uint64(data[48:56])
	om.SnapshotTreeOID = binary.LittleEndian.Uint64(data[56:64])
	om.MostRecentSnapXID = binary.LittleEndian.Uint64(data[64:72])

	// Parse remaining fields for completeness
	om.Checksum = binary.LittleEndian.Uint64(data[0:8])
	om.OID = binary.LittleEndian.Uint64(data[8:16])
	om.XID = binary.LittleEndian.Uint64(data[16:24])
	om.Flags = binary.LittleEndian.Uint32(data[32:36])
	om.TreeType = binary.LittleEndian.Uint32(data[40:44])
	om.SnapshotTreeType = binary.LittleEndian.Uint32(data[44:48])
	om.Unknown2 = binary.LittleEndian.Uint64(data[72:80])
	om.Unknown3 = binary.LittleEndian.Uint64(data[80:88])

	if isVerbose() {
		notifyPrintf("%s: object checksum\t\t\t\t: 0x%08x\n", "ReadData", om.Checksum)
		notifyPrintf("%s: object identifier\t\t\t: %d\n", "ReadData", om.OID)
		notifyPrintf("%s: object transaction identifier\t\t: %d\n", "ReadData", om.XID)
		notifyPrintf("%s: object type\t\t\t\t: 0x%08x\n", "ReadData", om.ObjectType)
		notifyPrintf("%s: object subtype\t\t\t\t: 0x%08x\n", "ReadData", om.ObjectSubtype)
		notifyPrintf("%s: flags\t\t\t\t\t: 0x%08x\n", "ReadData", om.Flags)
		notifyPrintf("%s: number of snapshots\t\t\t: %d\n", "ReadData", om.SnapshotCount)
		notifyPrintf("%s: B-tree type\t\t\t\t: 0x%08x\n", "ReadData", om.TreeType)
		notifyPrintf("%s: snapshots B-tree type\t\t\t: 0x%08x\n", "ReadData", om.SnapshotTreeType)
		notifyPrintf("%s: B-tree block number\t\t\t: %d\n", "ReadData", om.TreeOID)
		notifyPrintf("%s: snapshots B-tree block number\t\t: %d\n", "ReadData", om.SnapshotTreeOID)
		notifyPrintf("%s: most recent snapshot identifier\t\t: %d\n", "ReadData", om.MostRecentSnapXID)
		notifyPrintf("%s: unknown2\t\t\t\t: %d\n", "ReadData", om.Unknown2)
		notifyPrintf("%s: unknown3\t\t\t\t: %d\n", "ReadData", om.Unknown3)
		notifyPrintf("\n")
	}

	return nil
}

// NumberOfSnapshots retrieves the number of snapshots
func (om *ObjectMap) NumberOfSnapshots() (uint32, error) {
	if om == nil {
		return 0, fmt.Errorf("invalid object map")
	}
	return om.SnapshotCount, nil
}

// TreeOIDValue retrieves the B-tree block number
func (om *ObjectMap) TreeOIDValue() (uint64, error) {
	if om == nil {
		return 0, fmt.Errorf("invalid object map")
	}
	return om.TreeOID, nil
}

// SnapshotTreeOIDValue retrieves the snapshots B-tree block number
func (om *ObjectMap) SnapshotTreeOIDValue() (uint64, error) {
	if om == nil {
		return 0, fmt.Errorf("invalid object map")
	}
	return om.SnapshotTreeOID, nil
}

// MostRecentSnapXIDValue retrieves the most recent snapshot identifier
func (om *ObjectMap) MostRecentSnapXIDValue() (uint64, error) {
	if om == nil {
		return 0, fmt.Errorf("invalid object map")
	}
	return om.MostRecentSnapXID, nil
}
