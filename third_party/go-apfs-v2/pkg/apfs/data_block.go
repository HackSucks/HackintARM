package apfs

import (
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// DataBlock represents a data block that can be read from disk
type DataBlock struct {
	// The data buffer
	Data []byte

	// The data size
	DataSize int
}

// Maximum allocation size for data blocks (safety limit)
const MaxDataBlockSize = 1024 * 1024 * 1024 // 1GB

// NewDataBlock creates a new data block with the specified size
func NewDataBlock(size int) (*DataBlock, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid data block size: %d", size)
	}

	if size > MaxDataBlockSize {
		return nil, fmt.Errorf("invalid data size value exceeds maximum allocation size: %d > %d", size, MaxDataBlockSize)
	}

	return &DataBlock{
		Data:     make([]byte, size),
		DataSize: size,
	}, nil
}

// Close releases resources associated with the data block
// This method clears sensitive data before allowing garbage collection
func (db *DataBlock) Close() error {
	if db == nil {
		return fmt.Errorf("invalid data block")
	}

	// Clear sensitive data before freeing
	if db.Data != nil {
		// Clear the buffer to prevent sensitive data from remaining in memory
		for i := range db.Data {
			db.Data[i] = 0
		}
		db.Data = nil
	}

	db.DataSize = 0

	return nil
}

// Clear clears the data in the block
func (db *DataBlock) Clear() error {
	if db == nil {
		return fmt.Errorf("invalid data block")
	}

	if db.Data == nil {
		return fmt.Errorf("invalid data block - missing data")
	}

	if db.DataSize > common.Int32Max {
		return fmt.Errorf("invalid data block - data size value out of bounds")
	}

	// Clear the buffer
	for i := range db.Data {
		db.Data[i] = 0
	}

	return nil
}

// Read reads the data block from disk at the specified offset
func (db *DataBlock) Read(
	reader io.ReaderAt,
	ioHandle *IOHandle,
	encryptionContext *EncryptionContext,
	offset int64,
	encryptionIdentifier uint64,
) error {
	if db == nil {
		return fmt.Errorf("invalid data block")
	}

	if db.Data == nil {
		return fmt.Errorf("invalid data block - missing data")
	}

	if db.DataSize > common.Int32Max {
		return fmt.Errorf("invalid data block - data size value out of bounds")
	}

	if ioHandle == nil {
		return fmt.Errorf("invalid IO handle")
	}

	if ioHandle.BytesPerSector == 0 {
		return fmt.Errorf("invalid IO handle - missing bytes per sector")
	}

	if reader == nil {
		return fmt.Errorf("invalid file handle")
	}

	var readBuffer []byte
	var err error

	// If encryption is enabled, we need a temporary buffer
	if encryptionContext != nil {
		readBuffer = make([]byte, db.DataSize)
	} else {
		readBuffer = db.Data
	}

	// Read data from disk
	n, err := reader.ReadAt(readBuffer, offset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read data block at offset %d: %w", offset, err)
	}

	if n != db.DataSize {
		return fmt.Errorf("unable to read data block at offset %d: expected %d bytes, got %d", offset, db.DataSize, n)
	}

	// Decrypt if encryption context is provided
	if encryptionContext != nil {
		// Calculate sector number for encryption
		// This matches the C implementation: encryption_identifier *= data_block->data_size; encryption_identifier /= io_handle->bytes_per_sector;
		sectorNumber := (encryptionIdentifier * uint64(db.DataSize)) / uint64(ioHandle.BytesPerSector)

		// Decrypt the data
		err = encryptionContext.Decrypt(
			readBuffer,
			db.Data,
			sectorNumber,
			ioHandle.BytesPerSector,
		)
		if err != nil {
			return fmt.Errorf("unable to decrypt data block: %w", err)
		}
	}

	return nil
}

// ReadBTreeNode reads a B-tree node from a data block
// This is a convenience function that reads a block and then parses it as a B-tree node
func ReadBTreeNode(
	reader io.ReaderAt,
	ioHandle *IOHandle,
	encryptionContext *EncryptionContext,
	blockNumber uint64,
) (*BTreeNode, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	// Serve repeated reads of the same node from the cache. Traversals
	// re-descend from the root constantly, so this avoids re-reading and
	// re-parsing the same blocks from disk. Cached nodes are read-only.
	if node := ioHandle.getCachedNode(blockNumber); node != nil {
		return node, nil
	}

	// Calculate offset
	offset := int64(blockNumber * uint64(ioHandle.BlockSize))

	// Create data block
	dataBlock, err := NewDataBlock(int(ioHandle.BlockSize))
	if err != nil {
		return nil, fmt.Errorf("unable to create data block: %w", err)
	}

	// Read the block
	err = dataBlock.Read(reader, ioHandle, encryptionContext, offset, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("unable to read data block: %w", err)
	}

	// Parse as B-tree node
	node := NewBTreeNode()
	err = node.ReadData(dataBlock.Data)
	if err != nil {
		return nil, fmt.Errorf("unable to read B-tree node: %w", err)
	}

	ioHandle.putCachedNode(blockNumber, node)

	return node, nil
}
