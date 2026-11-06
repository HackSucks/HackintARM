// Volume keybag functions
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// VolumeKeybag represents an APFS volume keybag
type VolumeKeybag struct {
	Entries []*KeybagEntry
}

// NewVolumeKeybag creates a new volume keybag
func NewVolumeKeybag() (*VolumeKeybag, error) {
	return &VolumeKeybag{
		Entries: make([]*KeybagEntry, 0),
	}, nil
}

// Close releases resources associated with the volume keybag
func (v *VolumeKeybag) Close() error {
	if v == nil {
		return fmt.Errorf("invalid volume keybag")
	}

	// Clear entries (Go's GC will handle the cleanup)
	v.Entries = nil
	return nil
}

// ReadFrom reads the volume keybag from a file at the specified offset
func (v *VolumeKeybag) ReadFrom(
	ioHandle *IOHandle,
	reader io.ReaderAt,
	fileOffset int64,
	dataSize uint64,
	volumeIdentifier []byte,
) error {
	if v == nil {
		return fmt.Errorf("invalid volume keybag")
	}

	if ioHandle == nil {
		return fmt.Errorf("invalid IO handle")
	}

	if ioHandle.BytesPerSector == 0 {
		return fmt.Errorf("invalid IO handle - missing bytes per sector")
	}

	if dataSize == 0 || dataSize > common.Int32Max {
		return fmt.Errorf("invalid volume keybag size value out of bounds")
	}

	// Read encrypted data
	encryptedData := make([]byte, dataSize)

	if isVerbose() {
		notifyPrintf("%s: reading volume keybag data at offset: %d (0x%08x)\n",
			"ReadFrom", fileOffset, fileOffset)
	}

	n, err := reader.ReadAt(encryptedData, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read encrypted data at offset: %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}
	if n != int(dataSize) {
		return fmt.Errorf("unable to read encrypted data at offset: %d (0x%08x)",
			fileOffset, fileOffset)
	}

	// Decrypt the data using AES-128-XTS with volume identifier as both encryption and tweak key
	encryptionContext, err := NewEncryptionContext(uint32(EncryptionMethodAES128XTS))
	if err != nil {
		return fmt.Errorf("unable to initialize encryption context: %w", err)
	}

	if err := encryptionContext.SetKeys(volumeIdentifier[:16], volumeIdentifier[:16]); err != nil {
		return fmt.Errorf("unable to set keys in encryption context: %w", err)
	}

	data := make([]byte, dataSize)
	if err := encryptionContext.Crypt(
		CryptModeDecrypt,
		encryptedData,
		data,
		uint64(fileOffset/int64(ioHandle.BytesPerSector)),
		uint16(ioHandle.BytesPerSector),
	); err != nil {
		return fmt.Errorf("unable to decrypt data: %w", err)
	}

	if isVerbose() {
		notifyPrintf("%s: unencrypted volume keybag data:\n", "ReadFrom")
		PrintData(data, true)
	}

	// Read the decrypted data
	if err := v.ReadData(data); err != nil {
		return fmt.Errorf("unable to read volume keybag: %w", err)
	}

	return nil
}

// ReadData reads the volume keybag from binary data
func (v *VolumeKeybag) ReadData(data []byte) error {
	if v == nil {
		return fmt.Errorf("invalid volume keybag")
	}

	if len(data) < 32 || len(data) > common.Int32Max {
		return fmt.Errorf("invalid data size value out of bounds")
	}

	if isVerbose() {
		notifyPrintf("%s: volume keybag object data:\n", "ReadData")
		PrintData(data[:32], true)
	}

	// Parse object header (32 bytes)
	objectType := binary.LittleEndian.Uint32(data[24:28])
	objectSubtype := binary.LittleEndian.Uint32(data[28:32])

	// Object type should be 0x72656373 ("recs" in ASCII)
	if objectType != 0x72656373 {
		return fmt.Errorf("invalid object type: 0x%08x", objectType)
	}

	if objectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", objectSubtype)
	}

	if isVerbose() {
		objectChecksum := binary.LittleEndian.Uint64(data[0:8])
		oid := binary.LittleEndian.Uint64(data[8:16])
		objectTransactionIdentifier := binary.LittleEndian.Uint64(data[16:24])

		notifyPrintf("%s: object checksum\t\t\t: 0x%08x\n", "ReadData", objectChecksum)
		notifyPrintf("%s: object identifier\t\t\t: %d\n", "ReadData", oid)
		notifyPrintf("%s: object transaction identifier\t: %d\n", "ReadData", objectTransactionIdentifier)
		notifyPrintf("%s: object type\t\t\t\t: 0x%08x\n", "ReadData", objectType)
		notifyPrintf("%s: object subtype\t\t\t\t: 0x%08x\n", "ReadData", objectSubtype)
		notifyPrintf("\n")
	}

	dataOffset := 32

	// Read keybag header (16 bytes)
	bagHeader, err := NewKeybagHeader()
	if err != nil {
		return fmt.Errorf("unable to create keybag header: %w", err)
	}

	if err := bagHeader.ReadData(data[dataOffset:]); err != nil {
		return fmt.Errorf("unable to read keybag header: %w", err)
	}

	if int(bagHeader.DataSize) > len(data)-dataOffset {
		return fmt.Errorf("invalid keybag header data size value out of bounds")
	}

	dataOffset += 16

	// Read all entries
	for bagEntryIndex := uint16(0); bagEntryIndex < bagHeader.NumberOfEntries; bagEntryIndex++ {
		bagEntry, err := NewKeybagEntry()
		if err != nil {
			return fmt.Errorf("unable to create keybag entry: %d: %w", bagEntryIndex, err)
		}

		if err := bagEntry.ReadData(data[dataOffset:]); err != nil {
			return fmt.Errorf("unable to read keybag entry: %d: %w", bagEntryIndex, err)
		}

		v.Entries = append(v.Entries, bagEntry)

		dataOffset += bagEntry.Size

		// Handle 16-byte alignment padding
		alignmentPaddingSize := dataOffset % 16
		if alignmentPaddingSize != 0 {
			alignmentPaddingSize = 16 - alignmentPaddingSize

			if alignmentPaddingSize > len(data) || dataOffset > len(data)-alignmentPaddingSize {
				return fmt.Errorf("invalid data size value out of bounds")
			}

			if isVerbose() {
				notifyPrintf("%s: alignment padding data:\n", "ReadData")
				PrintData(data[dataOffset:dataOffset+alignmentPaddingSize], true)
			}

			dataOffset += alignmentPaddingSize
		}
	}

	return nil
}

// VolumeKey retrieves the volume key that can be unlocked with the given passwords
// Returns true and the key if successful, false if no key could be unlocked
func (v *VolumeKeybag) VolumeKey(
	userPassword []byte,
	recoveryPassword []byte,
) ([]byte, bool, error) {
	if v == nil {
		return nil, false, fmt.Errorf("invalid volume keybag")
	}

	// Iterate through all entries looking for type 3 (KEK entries)
	for entryIndex, bagEntry := range v.Entries {
		if bagEntry == nil {
			return nil, false, fmt.Errorf("missing entry: %d", entryIndex)
		}

		// Type 3 is the key encryption key (KEK) entry
		if bagEntry.Type != 3 {
			continue
		}

		// Parse the key encryption key
		keyEncryptedKey, err := NewKeyEncryptionKey()
		if err != nil {
			return nil, false, fmt.Errorf("unable to create key encryption key: %w", err)
		}

		if err := keyEncryptedKey.ReadData(bagEntry.Data); err != nil {
			return nil, false, fmt.Errorf("unable to read key encryption key: %w", err)
		}

		// Try to unlock with user password first
		if len(userPassword) > 0 {
			key, err := keyEncryptedKey.UnlockWithPassword(userPassword)
			if err == nil && key != nil {
				return key, true, nil
			}
		}

		// Try recovery password if user password failed
		if len(recoveryPassword) > 0 {
			key, err := keyEncryptedKey.UnlockWithPassword(recoveryPassword)
			if err == nil && key != nil {
				return key, true, nil
			}
		}
	}

	// No key could be unlocked
	return nil, false, nil
}
