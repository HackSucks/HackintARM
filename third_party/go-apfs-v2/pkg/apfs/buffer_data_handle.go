package apfs

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// BufferDataHandle represents a buffer data handle for reading from a byte buffer
type BufferDataHandle struct {
	// The current offset in the buffer
	CurrentOffset int64

	// The data buffer
	Data []byte
}

// NewBufferDataHandle creates a new buffer data handle
func NewBufferDataHandle(data []byte) (*BufferDataHandle, error) {
	if len(data) > 0 && data == nil {
		return nil, fmt.Errorf("invalid data")
	}

	if int64(len(data)) > common.Int32Max {
		return nil, fmt.Errorf("invalid data size value exceeds maximum")
	}

	return &BufferDataHandle{
		CurrentOffset: 0,
		Data:          data,
	}, nil
}

// ReadSegmentData reads data from the current offset into a buffer
// This is a callback function for the data stream
func (bdh *BufferDataHandle) ReadSegmentData(
	segmentIndex int,
	segmentData []byte,
) (int, error) {
	if bdh == nil {
		return 0, fmt.Errorf("invalid buffer data handle")
	}

	if bdh.CurrentOffset < 0 {
		return 0, fmt.Errorf("invalid data handle - current offset value out of bounds")
	}

	if segmentIndex != 0 {
		return 0, fmt.Errorf("invalid segment index value out of bounds")
	}

	if segmentData == nil {
		return 0, fmt.Errorf("invalid segment data")
	}

	if int64(len(segmentData)) > common.Int32Max {
		return 0, fmt.Errorf("invalid segment data size value exceeds maximum")
	}

	// Check if we're past the end of the buffer
	if bdh.CurrentOffset >= int64(len(bdh.Data)) {
		return 0, nil
	}

	// Calculate how much data we can read
	readSize := int64(len(bdh.Data)) - bdh.CurrentOffset

	if readSize > int64(len(segmentData)) {
		readSize = int64(len(segmentData))
	}

	// Copy data
	copy(segmentData, bdh.Data[bdh.CurrentOffset:bdh.CurrentOffset+readSize])

	// Update offset
	bdh.CurrentOffset += readSize

	return int(readSize), nil
}

// SeekSegmentOffset seeks to a specific offset in the data
// This is a callback function for the data stream
func (bdh *BufferDataHandle) SeekSegmentOffset(
	segmentIndex int,
	segmentOffset int64,
) (int64, error) {
	if bdh == nil {
		return 0, fmt.Errorf("invalid buffer data handle")
	}

	if segmentIndex != 0 {
		return 0, fmt.Errorf("invalid segment index value out of bounds")
	}

	if segmentOffset < 0 {
		return 0, fmt.Errorf("invalid segment offset value out of bounds")
	}

	bdh.CurrentOffset = segmentOffset

	return segmentOffset, nil
}
