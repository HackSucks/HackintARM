// The APFS data block data handle implementation
package apfs

import (
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// DataBlockDataHandle represents a data handle for reading data through data blocks
// This is used for reading file data that spans multiple data blocks
type DataBlockDataHandle struct {
	// The current offset in the data stream
	CurrentOffset int64

	// The total data size
	DataSize uint64

	// The file system data handle
	FileSystemDataHandle *FileSystemDataHandle

	// The data block vector
	DataBlockVector *DataBlockVector
}

// NewDataBlockDataHandle creates a new data block data handle
func NewDataBlockDataHandle(
	ioHandle *IOHandle,
	encryptionContext *EncryptionContext,
	fileExtents []*FileExtent,
	isSparse bool,
) (*DataBlockDataHandle, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	// Create file system data handle
	fileSystemDataHandle, err := NewFileSystemDataHandle(ioHandle, encryptionContext, fileExtents)
	if err != nil {
		return nil, fmt.Errorf("unable to create file system data handle: %w", err)
	}

	// Create data block vector
	dataBlockVector, err := NewDataBlockVector(ioHandle, fileSystemDataHandle, fileExtents, isSparse)
	if err != nil {
		return nil, fmt.Errorf("unable to create data block vector: %w", err)
	}

	// Get the total size from the vector
	dataSize, err := dataBlockVector.Size()
	if err != nil {
		dataBlockVector.Close()
		return nil, fmt.Errorf("unable to retrieve size of data block vector: %w", err)
	}

	return &DataBlockDataHandle{
		CurrentOffset:        0,
		DataSize:             dataSize,
		FileSystemDataHandle: fileSystemDataHandle,
		DataBlockVector:      dataBlockVector,
	}, nil
}

// Close releases resources associated with the data block data handle
func (dh *DataBlockDataHandle) Close() error {
	if dh == nil {
		return fmt.Errorf("invalid data block data handle")
	}

	// Free the data block vector (which will also free cached blocks)
	if dh.DataBlockVector != nil {
		if err := dh.DataBlockVector.Close(); err != nil {
			return fmt.Errorf("unable to free data block vector: %w", err)
		}
		dh.DataBlockVector = nil
	}

	// Note: FileSystemDataHandle is not freed here as it's managed by the vector
	// and may be shared with other structures

	return nil
}

// ReadSegmentData reads data from the current offset into a buffer
// This is a callback function for the data stream
//
// Parameters:
//   - reader: The file handle to read from
//   - segmentIndex: The index of the segment (unused in this context)
//   - segmentFileIndex: The file index (unused in this context)
//   - segmentData: The buffer to read data into
//   - segmentDataSize: The size of the buffer
//   - segmentFlags: Flags for the segment (unused)
//   - readFlags: Flags for reading (unused)
//
// Returns the number of bytes read or error
func (dh *DataBlockDataHandle) ReadSegmentData(
	reader io.ReaderAt,
	segmentIndex int,
	segmentFileIndex int,
	segmentData []byte,
	segmentDataSize int,
	segmentFlags uint32,
	readFlags uint8,
) (int, error) {
	if dh == nil {
		return 0, fmt.Errorf("invalid data block data handle")
	}

	if dh.CurrentOffset < 0 {
		return 0, fmt.Errorf("invalid data block data handle - current offset value out of bounds")
	}

	if segmentIndex < 0 {
		return 0, fmt.Errorf("invalid segment index value out of bounds")
	}

	if segmentData == nil {
		return 0, fmt.Errorf("invalid segment data")
	}

	if segmentDataSize > common.Int32Max {
		return 0, fmt.Errorf("invalid segment data size value exceeds maximum")
	}

	// Check if we're at or past the end
	if uint64(dh.CurrentOffset) >= dh.DataSize {
		return 0, nil
	}

	segmentDataOffset := 0
	remainingSize := segmentDataSize

	// Read data block by block
	for remainingSize > 0 {
		// Get the data block at the current offset
		dataBlock, dataBlockOffset, err := dh.DataBlockVector.ElementValueAtOffset(
			reader,
			dh.CurrentOffset,
		)
		if err != nil {
			return 0, fmt.Errorf("unable to retrieve data block at offset %d: %w", dh.CurrentOffset, err)
		}

		if dataBlock == nil {
			return 0, fmt.Errorf("invalid data block")
		}

		if dataBlock.Data == nil {
			return 0, fmt.Errorf("invalid data block - missing data")
		}

		if dataBlockOffset < 0 || int(dataBlockOffset) >= dataBlock.DataSize {
			return 0, fmt.Errorf("invalid data block offset value out of bounds")
		}

		// Calculate how much to read from this block
		readSize := dataBlock.DataSize - int(dataBlockOffset)
		if readSize > remainingSize {
			readSize = remainingSize
		}

		// Copy data from the block
		copy(segmentData[segmentDataOffset:segmentDataOffset+readSize],
			dataBlock.Data[dataBlockOffset:int(dataBlockOffset)+readSize])

		segmentDataOffset += readSize
		remainingSize -= readSize
		dh.CurrentOffset += int64(readSize)

		// Check if we've reached the end
		if uint64(dh.CurrentOffset) >= dh.DataSize {
			break
		}
	}

	return segmentDataOffset, nil
}

// SeekSegmentOffset seeks to a certain offset in the data
// This is a callback function for the data stream
//
// Parameters:
//   - reader: The file handle (unused)
//   - segmentIndex: The index of the segment (unused)
//   - segmentFileIndex: The file index (unused)
//   - segmentOffset: The offset to seek to
//
// Returns the new offset or error
func (dh *DataBlockDataHandle) SeekSegmentOffset(
	reader io.ReaderAt,
	segmentIndex int,
	segmentFileIndex int,
	segmentOffset int64,
) (int64, error) {
	if dh == nil {
		return 0, fmt.Errorf("invalid data block data handle")
	}

	if segmentIndex < 0 {
		return 0, fmt.Errorf("invalid segment index value out of bounds")
	}

	if segmentOffset < 0 {
		return 0, fmt.Errorf("invalid segment offset value out of bounds")
	}

	dh.CurrentOffset = segmentOffset

	return segmentOffset, nil
}

// Size returns the total data size
func (dh *DataBlockDataHandle) Size() uint64 {
	if dh == nil {
		return 0
	}
	return dh.DataSize
}
