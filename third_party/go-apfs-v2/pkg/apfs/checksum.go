package apfs

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// CalculateFletcher64 calculates the Fletcher 64 checksum of a buffer of data
func CalculateFletcher64(buffer []byte, initialValue uint64) (uint64, error) {
	if buffer == nil {
		return 0, fmt.Errorf("invalid buffer")
	}

	if int64(len(buffer)) > common.Int32Max {
		return 0, fmt.Errorf("invalid size value exceeds maximum")
	}

	if len(buffer)%4 != 0 {
		return 0, fmt.Errorf("invalid size value out of bounds: size must be multiple of 4")
	}

	lower32bit := initialValue & common.Uint32Mask
	upper32bit := (initialValue >> 32) & common.Uint32Mask

	for bufferOffset := 0; bufferOffset < len(buffer); bufferOffset += 4 {
		value32bit := binary.LittleEndian.Uint32(buffer[bufferOffset : bufferOffset+4])

		lower32bit += uint64(value32bit)
		upper32bit += lower32bit
	}

	lower32bit %= common.Uint32Mask
	upper32bit %= common.Uint32Mask

	value32bit := uint64(common.Uint32Mask - ((lower32bit + upper32bit) % common.Uint32Mask))
	upper32bit = uint64(common.Uint32Mask - ((lower32bit + value32bit) % common.Uint32Mask))

	return (upper32bit << 32) | value32bit, nil
}

// ValidateChecksum validates the Fletcher 64 checksum of an APFS object
// Returns true if the checksum is valid (non-zero and correct)
func ValidateChecksum(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	// Extract stored checksum
	storedChecksum := binary.LittleEndian.Uint64(data[0:8])

	// Zero checksum is invalid
	if storedChecksum == 0 {
		return false
	}

	// Calculate checksum of data (excluding the checksum field itself)
	calculated, err := CalculateFletcher64(data[8:], 0)
	if err != nil {
		return false
	}

	return calculated == storedChecksum
}
