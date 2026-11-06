// MD5 hash calculation for APFS file entries
package tools

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

// CalculateMD5Hash calculates the MD5 hash of a file entry's data
func CalculateMD5Hash(entry *apfs.FileEntry) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("invalid file entry")
	}

	// Get the file size
	size, err := entry.DataSize()
	if err != nil {
		return "", fmt.Errorf("unable to get file size: %w", err)
	}

	// Empty files have a specific MD5
	if size == 0 {
		return "d41d8cd98f00b204e9800998ecf8427e", nil // MD5 of empty string
	}

	// Create MD5 hasher
	hasher := md5.New()

	// Read file data in chunks and hash it
	buffer := make([]byte, 65536) // 64KB buffer
	totalRead := int64(0)

	for totalRead < size {
		bytesToRead := int64(len(buffer))
		if totalRead+bytesToRead > size {
			bytesToRead = size - totalRead
		}

		n, err := entry.Read(buffer[:bytesToRead])
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("unable to read file data: %w", err)
		}

		if n == 0 {
			break
		}

		hasher.Write(buffer[:n])
		totalRead += int64(n)

		if err == io.EOF {
			break
		}
	}

	// Get the hash
	hashBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashBytes), nil
}

// DigestHashToString converts a digest hash byte array to a hex string
func DigestHashToString(hash []byte) string {
	return hex.EncodeToString(hash)
}

// StringToDigestHash converts a hex string to a byte array
func StringToDigestHash(hashString string) ([]byte, error) {
	return hex.DecodeString(hashString)
}
