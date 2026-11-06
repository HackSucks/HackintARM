// The APFS chunk-info block definition
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// ChunkInfoBlockSize is the size of the chunk-info block in bytes
const ChunkInfoBlockSize = 4096

// ChunkInfoBlock represents the APFS chunk-info block structure
type ChunkInfoBlock struct {
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

// NewChunkInfoBlock creates a new chunk-info block
func NewChunkInfoBlock() *ChunkInfoBlock {
	return &ChunkInfoBlock{}
}

// ReadFrom reads the chunk-info block from a file handle at the specified offset
func (cib *ChunkInfoBlock) ReadFrom(reader io.ReaderAt, fileOffset int64) error {
	if cib == nil {
		return fmt.Errorf("invalid chunk-info block")
	}

	// Allocate 4096 bytes for chunk-info block data
	chunkInformationBlockData := make([]byte, ChunkInfoBlockSize)

	// Read data from file
	n, err := reader.ReadAt(chunkInformationBlockData, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read chunk-info block data at offset %d: %w", fileOffset, err)
	}

	if n != ChunkInfoBlockSize {
		return fmt.Errorf("unable to read complete chunk-info block data: expected %d bytes, got %d", ChunkInfoBlockSize, n)
	}

	// Parse the data
	if err := cib.ReadData(chunkInformationBlockData); err != nil {
		return fmt.Errorf("unable to read chunk-info block data: %w", err)
	}

	return nil
}

// ReadData reads the chunk-info block from binary data
func (cib *ChunkInfoBlock) ReadData(data []byte) error {
	if cib == nil {
		return fmt.Errorf("invalid chunk-info block")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 32 || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	// Read chunk-info block header fields
	cib.Checksum = binary.LittleEndian.Uint64(data[0:8])
	cib.OID = binary.LittleEndian.Uint64(data[8:16])
	cib.XID = binary.LittleEndian.Uint64(data[16:24])
	cib.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	cib.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])
	cib.Unknown1 = binary.LittleEndian.Uint32(data[32:36])

	// Validate object type
	if cib.ObjectType != 0x40000007 {
		return fmt.Errorf("invalid object type: 0x%08x", cib.ObjectType)
	}

	// Validate object subtype
	if cib.ObjectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", cib.ObjectSubtype)
	}

	return nil
}
