package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Container keybag object type
const ContainerKeybagObjectType = 0x6b657973 // 'keys'

// Keybag entry types
const (
	KeybagEntryTypeUnknown         = 0
	KeybagEntryTypeVolumeKey       = 2 // Volume master key (encrypted)
	KeybagEntryTypeVolumeKeyExtent = 3 // Volume keybag extent location
)

// ContainerKeybag represents an APFS container keybag
type ContainerKeybag struct {
	// The entries array
	Entries []*KeybagEntry

	// Value to indicate if the container keybag is locked
	IsLocked bool
}

// KeybagEntry represents a single keybag entry
type KeybagEntry struct {
	// The identifier (UUID)
	Identifier [16]byte

	// The entry type
	Type uint16

	// The entry data
	Data []byte

	// The data size
	DataSize uint16

	// The total size including header
	Size int
}

// NewKeybagEntry creates a new keybag entry
func NewKeybagEntry() (*KeybagEntry, error) {
	return &KeybagEntry{
		Identifier: [16]byte{},
		Type:       0,
		Data:       nil,
		DataSize:   0,
		Size:       0,
	}, nil
}

// ReadData reads a keybag entry from binary data
func (e *KeybagEntry) ReadData(data []byte) error {
	if e == nil {
		return fmt.Errorf("invalid keybag entry")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 24 {
		return fmt.Errorf("invalid data size: expected at least 24 bytes for entry header, got %d", len(data))
	}

	// Read entry header (24 bytes)
	copy(e.Identifier[:], data[0:16])
	e.Type = binary.LittleEndian.Uint16(data[16:18])
	e.DataSize = binary.LittleEndian.Uint16(data[18:20])
	// Unknown1 at offset 20-24 is not stored in KeybagEntry

	// Verify we have enough data for the entry data
	totalSize := 24 + int(e.DataSize)
	if len(data) < totalSize {
		return fmt.Errorf("invalid data size: expected at least %d bytes (header + data), got %d", totalSize, len(data))
	}

	// Read entry data
	if e.DataSize > 0 {
		e.Data = make([]byte, e.DataSize)
		copy(e.Data, data[24:24+e.DataSize])
	}

	// Set total size
	e.Size = totalSize

	return nil
}

// NewContainerKeybag creates a new container keybag
func NewContainerKeybag() (*ContainerKeybag, error) {
	return &ContainerKeybag{
		Entries:  make([]*KeybagEntry, 0),
		IsLocked: false,
	}, nil
}

// Close releases resources associated with the container keybag
func (ckb *ContainerKeybag) Close() error {
	if ckb == nil {
		return fmt.Errorf("invalid container keybag")
	}

	// Clear entries
	ckb.Entries = nil
	return nil
}

// ReadFrom reads the container keybag from a file
func (ckb *ContainerKeybag) ReadFrom(
	ioHandle *IOHandle,
	reader io.ReaderAt,
	fileOffset int64,
	dataSize uint64,
	containerIdentifier []byte,
) error {
	if ckb == nil {
		return fmt.Errorf("invalid container keybag")
	}

	if ioHandle == nil {
		return fmt.Errorf("invalid IO handle")
	}

	if ioHandle.BytesPerSector == 0 {
		return fmt.Errorf("invalid IO handle - missing bytes per sector")
	}

	if dataSize == 0 || dataSize > 0x7FFFFFFF { // Max reasonable size
		return fmt.Errorf("invalid container keybag size value out of bounds")
	}

	// Read encrypted data
	encryptedData := make([]byte, dataSize)
	n, err := reader.ReadAt(encryptedData, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read encrypted data at offset %d: %w", fileOffset, err)
	}
	if n != int(dataSize) {
		return fmt.Errorf("unable to read complete encrypted data: expected %d bytes, got %d", dataSize, n)
	}

	// Allocate buffer for decrypted data
	data := make([]byte, dataSize)

	// Create encryption context using AES-128-XTS with container identifier
	encryptionContext, err := NewEncryptionContext(uint32(EncryptionMethodAES128XTS))
	if err != nil {
		return fmt.Errorf("unable to create encryption context: %w", err)
	}

	// Use container identifier as both key and tweak key (first 16 bytes)
	if len(containerIdentifier) < 16 {
		return fmt.Errorf("invalid container identifier: must be at least 16 bytes")
	}

	err = encryptionContext.SetKeys(containerIdentifier[:16], containerIdentifier[:16])
	if err != nil {
		return fmt.Errorf("unable to set keys in encryption context: %w", err)
	}

	// Decrypt the data
	sectorNumber := uint64(fileOffset) / uint64(ioHandle.BytesPerSector)
	err = encryptionContext.Decrypt(encryptedData, data, sectorNumber, ioHandle.BytesPerSector)
	if err != nil {
		return fmt.Errorf("unable to decrypt data: %w", err)
	}

	// Parse the decrypted data
	return ckb.ReadData(data)
}

// ReadData reads the container keybag from decrypted data
func (ckb *ContainerKeybag) ReadData(data []byte) error {
	if ckb == nil {
		return fmt.Errorf("invalid container keybag")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < 32 { // Minimum: object header (32)
		return fmt.Errorf("invalid data size value out of bounds")
	}

	// Read object header (first 32 bytes)
	storedChecksum := binary.LittleEndian.Uint64(data[0:8])
	objectType := binary.LittleEndian.Uint32(data[24:28])
	objectSubtype := binary.LittleEndian.Uint32(data[28:32])

	// Verify object type
	if objectType != ContainerKeybagObjectType {
		return fmt.Errorf("invalid object type: 0x%08x (expected 0x%08x)", objectType, ContainerKeybagObjectType)
	}

	// Verify object subtype
	if objectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", objectSubtype)
	}

	// Verify checksum
	calculatedChecksum, err := CalculateFletcher64(data[8:], 0)
	if err != nil {
		return fmt.Errorf("unable to calculate Fletcher 64 checksum: %w", err)
	}

	if storedChecksum != calculatedChecksum {
		return fmt.Errorf("checksum mismatch (0x%016x != 0x%016x)", storedChecksum, calculatedChecksum)
	}

	dataOffset := 32 // After object header

	// Read keybag header using KeybagHeader.ReadData()
	if len(data) < dataOffset+16 {
		return fmt.Errorf("insufficient data for keybag header")
	}

	header, err := NewKeybagHeader()
	if err != nil {
		return fmt.Errorf("unable to create keybag header: %w", err)
	}

	if err := header.ReadData(data[dataOffset:]); err != nil {
		return fmt.Errorf("unable to read keybag header: %w", err)
	}

	dataOffset += 16 // Keybag header size

	if int(header.DataSize) > len(data)-dataOffset {
		return fmt.Errorf("invalid keybag header data size value out of bounds")
	}

	// Read keybag entries using KeybagEntry.ReadData()
	for i := uint16(0); i < header.NumberOfEntries; i++ {
		if len(data) < dataOffset+24 { // Minimum entry header size
			return fmt.Errorf("insufficient data for keybag entry %d", i)
		}

		entry, err := NewKeybagEntry()
		if err != nil {
			return fmt.Errorf("unable to create keybag entry %d: %w", i, err)
		}

		// Read entry using the new ReadData method
		if err := entry.ReadData(data[dataOffset:]); err != nil {
			return fmt.Errorf("unable to read keybag entry %d: %w", i, err)
		}

		// Advance offset by the entry size
		dataOffset += entry.Size

		// Add entry to array
		ckb.Entries = append(ckb.Entries, entry)

		// Handle alignment padding (entries are aligned to 16-byte boundaries)
		alignmentPaddingSize := dataOffset % 16
		if alignmentPaddingSize != 0 {
			alignmentPaddingSize = 16 - alignmentPaddingSize

			if dataOffset+alignmentPaddingSize > len(data) {
				return fmt.Errorf("invalid data size for alignment padding")
			}

			dataOffset += alignmentPaddingSize
		}
	}

	return nil
}

// VolumeKeybagExtentByIdentifier retrieves the volume keybag extent for a specific volume
// Returns block number and number of blocks, or error
func (ckb *ContainerKeybag) VolumeKeybagExtentByIdentifier(
	volumeIdentifier []byte,
) (blockNumber uint64, numberOfBlocks uint64, found bool, err error) {
	if ckb == nil {
		return 0, 0, false, fmt.Errorf("invalid container keybag")
	}

	if len(volumeIdentifier) != 16 {
		return 0, 0, false, fmt.Errorf("invalid volume identifier: must be 16 bytes")
	}

	// Search for matching entry
	for _, entry := range ckb.Entries {
		// Check if this is a volume key extent entry
		if entry.Type != KeybagEntryTypeVolumeKeyExtent {
			continue
		}

		// Check if identifier matches
		if !bytes.Equal(entry.Identifier[:], volumeIdentifier) {
			continue
		}

		// Verify data size
		if len(entry.Data) != 16 {
			return 0, 0, false, fmt.Errorf("invalid entry data size: expected 16 bytes, got %d", len(entry.Data))
		}

		// Parse extent data
		blockNumber = binary.LittleEndian.Uint64(entry.Data[0:8])
		numberOfBlocks = binary.LittleEndian.Uint64(entry.Data[8:16])

		return blockNumber, numberOfBlocks, true, nil
	}

	return 0, 0, false, nil // Not found
}

// VolumeMasterKeyByIdentifier retrieves the volume master key for a specific volume
// Returns the decrypted master key, or error
func (ckb *ContainerKeybag) VolumeMasterKeyByIdentifier(
	volumeIdentifier []byte,
	volumeKey []byte,
) (masterKey []byte, found bool, err error) {
	if ckb == nil {
		return nil, false, fmt.Errorf("invalid container keybag")
	}

	if len(volumeIdentifier) != 16 {
		return nil, false, fmt.Errorf("invalid volume identifier: must be 16 bytes")
	}

	// Search for matching entry
	for _, entry := range ckb.Entries {
		// Check if this is a volume key entry
		if entry.Type != KeybagEntryTypeVolumeKey {
			continue
		}

		// Check if identifier matches
		if !bytes.Equal(entry.Identifier[:], volumeIdentifier) {
			continue
		}

		// Parse key encryption key from entry data
		kek, err := NewKeyEncryptionKey()
		if err != nil {
			return nil, false, fmt.Errorf("unable to create key encryption key: %w", err)
		}

		if err := kek.ReadData(entry.Data); err != nil {
			return nil, false, fmt.Errorf("unable to read key encryption key: %w", err)
		}

		// Unlock the key encryption key using the volume key
		masterKey, err = kek.UnlockWithKey(volumeKey)
		if err != nil {
			return nil, false, fmt.Errorf("unable to unlock key encryption key: %w", err)
		}

		return masterKey, true, nil
	}

	return nil, false, nil // Not found
}
