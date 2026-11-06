// Support functions for APFS
package apfs

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// AccessFlagsRead returns the access flags for reading
func AccessFlagsRead() AccessFlags {
	return AccessFlagRead
}

// CheckContainerSignature determines if a file contains an APFS container signature
// Returns true if the file has a valid container signature, false otherwise
func CheckContainerSignature(filename string) (bool, error) {
	if filename == "" {
		return false, fmt.Errorf("invalid filename")
	}

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return false, fmt.Errorf("unable to open file: %w", err)
	}
	defer file.Close()

	return CheckContainerSignatureReader(file)
}

// CheckVolumeSignature determines if a file contains an APFS volume signature
// Returns true if the file has a valid volume signature, false otherwise
func CheckVolumeSignature(filename string) (bool, error) {
	if filename == "" {
		return false, fmt.Errorf("invalid filename")
	}

	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		return false, fmt.Errorf("unable to open file: %w", err)
	}
	defer file.Close()

	return CheckVolumeSignatureReader(file)
}

// CheckContainerSignatureReader determines if a reader contains an APFS container signature
// Returns true if the reader has a valid container signature, false otherwise
func CheckContainerSignatureReader(reader io.ReaderAt) (bool, error) {
	if reader == nil {
		return false, fmt.Errorf("invalid reader")
	}

	// Read signature at offset 0 (36 bytes total, signature is at bytes 32-35)
	signature := make([]byte, 36)
	n, err := reader.ReadAt(signature, 0)
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("unable to read signature at offset: 0 (0x00000000): %w", err)
	}
	if n != 36 {
		return false, fmt.Errorf("unable to read signature at offset: 0 (0x00000000)")
	}

	// Check if the signature matches the container signature (bytes 32-35)
	// Container signature: "NXSB" (0x4E 0x58 0x53 0x42)
	if bytes.Equal(signature[32:36], ContainerSignature[:]) {
		return true, nil
	}

	return false, nil
}

// CheckVolumeSignatureReader determines if a reader contains an APFS volume signature
// Returns true if the reader has a valid volume signature, false otherwise
func CheckVolumeSignatureReader(reader io.ReaderAt) (bool, error) {
	if reader == nil {
		return false, fmt.Errorf("invalid reader")
	}

	// Read signature at offset 0 (36 bytes total, signature is at bytes 32-35)
	signature := make([]byte, 36)
	n, err := reader.ReadAt(signature, 0)
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("unable to read signature at offset: 0 (0x00000000): %w", err)
	}
	if n != 36 {
		return false, fmt.Errorf("unable to read signature at offset: 0 (0x00000000)")
	}

	// Check if the signature matches the volume signature (bytes 32-35)
	// Volume signature: "APSB" (0x41 0x50 0x53 0x42)
	if bytes.Equal(signature[32:36], VolumeSignature[:]) {
		return true, nil
	}

	return false, nil
}
