package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Container reaper object type
const ReaperObjectType = 0x80000011

// Reaper represents an APFS reaper
// The reaper is used for tracking blocks to be freed
type Reaper struct {
	// Dummy field - structure is currently not fully implemented
	// The reaper structure is read but not actively used in basic operations
	dummy int
}

// NewReaper creates a new reaper
func NewReaper() (*Reaper, error) {
	return &Reaper{
		dummy: 0,
	}, nil
}

// ReadFrom reads the reaper from a file
func (cr *Reaper) ReadFrom(
	reader io.ReaderAt,
	fileOffset int64,
) error {
	if cr == nil {
		return fmt.Errorf("invalid reaper")
	}

	// Container reaper structure is 40 bytes (object header)
	data := make([]byte, 40)
	n, err := reader.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read reaper data at offset %d: %w", fileOffset, err)
	}
	if n != 40 {
		return fmt.Errorf("unable to read complete reaper data: expected 40 bytes, got %d", n)
	}

	return cr.ReadData(data)
}

// ReadData reads the reaper from data
func (cr *Reaper) ReadData(data []byte) error {
	if cr == nil {
		return fmt.Errorf("invalid reaper")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 40 {
		return fmt.Errorf("invalid data size: expected at least 40 bytes, got %d", len(data))
	}

	// Read object type (offset 24)
	objectType := binary.LittleEndian.Uint32(data[24:28])
	if objectType != ReaperObjectType {
		return fmt.Errorf("invalid object type: 0x%08x (expected 0x%08x)", objectType, ReaperObjectType)
	}

	// Read object subtype (offset 28)
	objectSubtype := binary.LittleEndian.Uint32(data[28:32])
	if objectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", objectSubtype)
	}

	// Container reaper structure is currently minimal
	// The actual implementation would parse reaper-specific data here
	// For now, we just validate the object type

	return nil
}
