// Password functions for APFS encryption
package apfs

import (
	"crypto/sha256"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2 computes a PBKDF2-derived key from the given input using HMAC-SHA256
//
// Parameters:
//   - password: The password to derive the key from
//   - salt: The salt value
//   - numberOfIterations: The number of PBKDF2 iterations
//   - outputSize: The desired output key size in bytes
//
// Returns the derived key or an error
func PBKDF2(password []byte, salt []byte, numberOfIterations uint32, outputSize int) ([]byte, error) {
	if password == nil {
		return nil, fmt.Errorf("invalid password")
	}

	if len(password) > common.Int32Max {
		return nil, fmt.Errorf("invalid password size value exceeds maximum")
	}

	if salt == nil {
		return nil, fmt.Errorf("invalid salt")
	}

	if len(salt) > common.Int32Max {
		return nil, fmt.Errorf("invalid salt size value exceeds maximum")
	}

	if numberOfIterations == 0 {
		return nil, fmt.Errorf("invalid number of iterations value zero or less")
	}

	if outputSize <= 0 {
		return nil, fmt.Errorf("invalid output data size")
	}

	if outputSize > common.Int32Max {
		return nil, fmt.Errorf("invalid output data size value exceeds maximum")
	}

	if isVerbose() {
		notifyPrintf("%s: password:\n", "PBKDF2")
		PrintData(password, false)

		notifyPrintf("%s: salt:\n", "PBKDF2")
		PrintData(salt, false)

		notifyPrintf("%s: number of iterations\t\t\t\t: %d\n", "PBKDF2", numberOfIterations)
		notifyPrintf("%s: output size\t\t\t\t\t: %d\n", "PBKDF2", outputSize)
		notifyPrintf("\n")
	}

	// Use Go's standard PBKDF2 implementation with HMAC-SHA256
	// This is equivalent to the manual implementation in the C code but more robust
	derivedKey := pbkdf2.Key(password, salt, int(numberOfIterations), outputSize, sha256.New)

	if isVerbose() {
		notifyPrintf("%s: derived key:\n", "PBKDF2")
		PrintData(derivedKey, false)
		notifyPrintf("\n")
	}

	return derivedKey, nil
}
