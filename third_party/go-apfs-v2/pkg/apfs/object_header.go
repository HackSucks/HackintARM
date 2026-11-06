// The APFS object definition
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// Object represents the APFS object structure
type ObjectHeader struct {
	// The checksum
	// Consists of 8 bytes
	Checksum uint64

	// The identifier
	// Consists of 8 bytes
	Identifier uint64

	// The transaction identifier
	// Consists of 8 bytes
	XID uint64

	// The type
	// Consists of 4 bytes
	Type uint32

	// The subtype
	// Consists of 4 bytes
	Subtype uint32
}

// ObjectHeaderSize is the size of an APFS object header in bytes
const ObjectHeaderSize = 32

// NewObjectHeader creates a new object
func NewObjectHeader() (*ObjectHeader, error) {
	return &ObjectHeader{}, nil
}

// ReadFrom reads the object from a file at the specified offset
func (o *ObjectHeader) ReadFrom(reader io.ReaderAt, fileOffset int64) error {
	if o == nil {
		return fmt.Errorf("invalid object")
	}

	if isVerbose() {
		notifyPrintf("%s: reading object at offset: %d (0x%08x)\n",
			"ReadFrom", fileOffset, fileOffset)
	}

	// Read object header (32 bytes)
	data := make([]byte, ObjectHeaderSize)
	n, err := reader.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read object data at offset: %d (0x%08x)", fileOffset, fileOffset)
	}
	if n != ObjectHeaderSize {
		return fmt.Errorf("unable to read object data at offset: %d (0x%08x)", fileOffset, fileOffset)
	}

	if err := o.ReadData(data); err != nil {
		return fmt.Errorf("unable to read object data: %w", err)
	}

	return nil
}

// ReadData reads the object from binary data
func (o *ObjectHeader) ReadData(data []byte) error {
	if o == nil {
		return fmt.Errorf("invalid object")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < ObjectHeaderSize || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	if isVerbose() {
		notifyPrintf("%s: object data:\n", "ReadData")
		PrintData(data[:ObjectHeaderSize], true)
	}

	// Parse object header
	o.Checksum = binary.LittleEndian.Uint64(data[0:8])
	o.Identifier = binary.LittleEndian.Uint64(data[8:16])
	o.XID = binary.LittleEndian.Uint64(data[16:24])
	o.Type = binary.LittleEndian.Uint32(data[24:28])
	o.Subtype = binary.LittleEndian.Uint32(data[28:32])

	if isVerbose() {
		notifyPrintf("%s: checksum\t\t\t\t\t: 0x%08x\n", "ReadData", o.Checksum)
		notifyPrintf("%s: identifier\t\t\t\t\t: %d\n", "ReadData", o.Identifier)
		notifyPrintf("%s: transaction identifier\t\t\t: %d\n", "ReadData", o.XID)
		notifyPrintf("%s: type\t\t\t\t\t: 0x%08x\n", "ReadData", o.Type)
		notifyPrintf("%s: subtype\t\t\t\t\t: 0x%08x\n", "ReadData", o.Subtype)
		notifyPrintf("\n")
	}

	return nil
}

// TransactionIdentifier retrieves the transaction identifier
func (o *ObjectHeader) TransactionIdentifier() (uint64, error) {
	if o == nil {
		return 0, fmt.Errorf("invalid object")
	}
	return o.XID, nil
}
