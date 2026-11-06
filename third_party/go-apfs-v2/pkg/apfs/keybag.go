// The APFS keybag definitions
package apfs

import (
	"encoding/binary"
	"fmt"
)

// KeybagHeader represents the APFS keybag header structure
type KeybagHeader struct {
	// The format version
	// Consists of 2 bytes
	FormatVersion uint16

	// The number of entries
	// Consists of 2 bytes
	NumberOfEntries uint16

	// The data size
	// Consists of 4 bytes
	DataSize uint32

	// Unknown
	// Consists of 8 bytes
	Unknown1 uint64
}

// KeybagEntryHeader represents the APFS keybag entry header structure
type KeybagEntryHeader struct {
	// The identifier
	// Consists of 16 bytes
	// Contains an UUID
	Identifier [16]byte

	// The entry type
	// Consists of 2 bytes
	EntryType uint16

	// The entry data size
	// Consists of 2 bytes
	DataSize uint16

	// Unknown
	// Consists of 4 bytes
	Unknown1 uint32
}

// NewKeybagHeader creates a new keybag header
func NewKeybagHeader() (*KeybagHeader, error) {
	return &KeybagHeader{
		FormatVersion:   0,
		NumberOfEntries: 0,
		DataSize:        0,
		Unknown1:        0,
	}, nil
}

// ReadData reads the keybag header from binary data
func (h *KeybagHeader) ReadData(data []byte) error {
	if h == nil {
		return fmt.Errorf("invalid keybag header")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 16 {
		return fmt.Errorf("invalid data size: expected at least 16 bytes, got %d", len(data))
	}

	// Read header fields (16 bytes total)
	h.FormatVersion = binary.LittleEndian.Uint16(data[0:2])
	h.NumberOfEntries = binary.LittleEndian.Uint16(data[2:4])
	h.DataSize = binary.LittleEndian.Uint32(data[4:8])
	h.Unknown1 = binary.LittleEndian.Uint64(data[8:16])

	// Validate format version (must be 2 according to C library)
	if h.FormatVersion != 2 {
		return fmt.Errorf("unsupported keybag header format version: %d (expected 2)", h.FormatVersion)
	}

	return nil
}

// NewKeybagEntryHeader creates a new keybag entry header
// Corresponds to the entry header portion of keybag_entry_t
func NewKeybagEntryHeader() (*KeybagEntryHeader, error) {
	return &KeybagEntryHeader{
		Identifier: [16]byte{},
		EntryType:  0,
		DataSize:   0,
		Unknown1:   0,
	}, nil
}

// ReadData reads the keybag entry header from binary data
// Corresponds to reading the header portion in KeybagEntry.ReadData
func (h *KeybagEntryHeader) ReadData(data []byte) error {
	if h == nil {
		return fmt.Errorf("invalid keybag entry header")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 24 {
		return fmt.Errorf("invalid data size: expected at least 24 bytes, got %d", len(data))
	}

	// Read entry header fields (24 bytes total)
	copy(h.Identifier[:], data[0:16])
	h.EntryType = binary.LittleEndian.Uint16(data[16:18])
	h.DataSize = binary.LittleEndian.Uint16(data[18:20])
	h.Unknown1 = binary.LittleEndian.Uint32(data[20:24])

	return nil
}
