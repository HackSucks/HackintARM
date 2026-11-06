package apfs

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// EncryptionContext represents an APFS encryption context
type EncryptionContext struct {
	// Method is the encryption method
	Method uint32

	// cipher1 is the AES cipher for data encryption/decryption
	cipher1 cipher.Block

	// cipher2 is the AES cipher for tweak encryption
	cipher2 cipher.Block
}

// NewEncryptionContext creates a new encryption context
func NewEncryptionContext(method uint32) (*EncryptionContext, error) {
	switch method {
	case uint32(EncryptionMethodAES128XTS), uint32(EncryptionMethodAES256XTS):
	default:
		return nil, fmt.Errorf("unsupported encryption method: %d", method)
	}

	return &EncryptionContext{
		Method: method,
	}, nil
}

// NewEncryptionContextForKey builds a context from a volume master key,
// choosing the cipher from the key's length.
//
// An XTS key is two keys end to end — one for the data, one for the tweak — so
// a 32-byte master key is AES-128-XTS and a 64-byte one is AES-256-XTS. The
// length is what says which, because the volume superblock's crypto fields
// describe per-file keys rather than the whole-volume key FileVault uses.
func NewEncryptionContextForKey(masterKey []byte) (*EncryptionContext, error) {
	var method EncryptionMethod
	switch len(masterKey) {
	case 32:
		method = EncryptionMethodAES128XTS
	case 64:
		method = EncryptionMethodAES256XTS
	default:
		return nil, fmt.Errorf("unexpected volume master key length %d: an XTS key is a data key and a tweak key together, so 32 or 64 bytes", len(masterKey))
	}

	context, err := NewEncryptionContext(uint32(method))
	if err != nil {
		return nil, err
	}
	half := len(masterKey) / 2
	if err := context.SetKeys(masterKey[:half], masterKey[half:]); err != nil {
		return nil, err
	}
	return context, nil
}

// SetKeys sets the de- and encryption keys
func (ec *EncryptionContext) SetKeys(key []byte, tweakKey []byte) error {
	if ec == nil {
		return fmt.Errorf("invalid context")
	}

	if key == nil {
		return fmt.Errorf("invalid key")
	}

	if tweakKey == nil {
		return fmt.Errorf("invalid tweak key")
	}

	// Determine required key size based on method
	var keyByteSize int
	switch ec.Method {
	case uint32(EncryptionMethodAES128XTS):
		keyByteSize = 16 // 128 bits
	case uint32(EncryptionMethodAES256XTS):
		keyByteSize = 32 // 256 bits
	default:
		return fmt.Errorf("unsupported encryption method: %d", ec.Method)
	}

	// Validate key sizes
	if len(key) < keyByteSize {
		return fmt.Errorf("invalid key value too small: got %d bytes, need at least %d bytes", len(key), keyByteSize)
	}

	if len(tweakKey) < keyByteSize {
		return fmt.Errorf("invalid tweak key value too small: got %d bytes, need at least %d bytes", len(tweakKey), keyByteSize)
	}

	// Initialize AES cipher blocks for decryption
	// Only use the required key bytes (first keyByteSize bytes)
	var err error
	ec.cipher1, err = aes.NewCipher(key[:keyByteSize])
	if err != nil {
		return fmt.Errorf("unable to set keys in decryption context: %w", err)
	}

	ec.cipher2, err = aes.NewCipher(tweakKey[:keyByteSize])
	if err != nil {
		return fmt.Errorf("unable to set keys in decryption context: %w", err)
	}

	return nil
}

// Crypt encrypts or decrypts a block of data
func (ec *EncryptionContext) Crypt(
	mode CryptMode,
	inputData []byte,
	outputData []byte,
	sectorNumber uint64,
	bytesPerSector uint16,
) error {
	if ec == nil {
		return fmt.Errorf("invalid context")
	}

	// Currently only decryption is supported
	if mode != CryptModeDecrypt {
		return fmt.Errorf("unsupported mode: %d", mode)
	}

	if inputData == nil {
		return fmt.Errorf("invalid input data")
	}

	if outputData == nil {
		return fmt.Errorf("invalid output data")
	}

	if len(outputData) < len(inputData) {
		return fmt.Errorf("invalid output data size smaller than input data size")
	}

	// Perform AES-XTS decryption sector by sector
	return ec.cryptXTS(inputData, outputData, sectorNumber, bytesPerSector)
}

// Decrypt is a convenience wrapper for Crypt with decrypt mode
func (ec *EncryptionContext) Decrypt(
	inputData []byte,
	outputData []byte,
	sectorNumber uint64,
	bytesPerSector uint16,
) error {
	return ec.Crypt(CryptModeDecrypt, inputData, outputData, sectorNumber, bytesPerSector)
}

// cryptXTS implements AES-XTS encryption/decryption
// This implements the XTS mode as used by libcaes_crypt_xts
func (ec *EncryptionContext) cryptXTS(
	inputData []byte,
	outputData []byte,
	sectorNumber uint64,
	bytesPerSector uint16,
) error {
	if ec.cipher1 == nil || ec.cipher2 == nil {
		return fmt.Errorf("AES ciphers not initialized")
	}

	sectorSize := int(bytesPerSector)
	dataOffset := 0

	// Process data sector by sector
	for dataOffset < len(inputData) {
		// Create tweak value from sector number (little-endian, padded with zeros)
		tweakValue := make([]byte, 16)
		binary.LittleEndian.PutUint64(tweakValue[0:8], sectorNumber)

		// Decrypt this sector using XTS mode
		if err := ec.decryptXTSSector(
			inputData[dataOffset:dataOffset+sectorSize],
			outputData[dataOffset:dataOffset+sectorSize],
			tweakValue,
		); err != nil {
			return fmt.Errorf("unable to decrypt data: %w", err)
		}

		dataOffset += sectorSize
		sectorNumber++
	}

	return nil
}

// decryptXTSSector decrypts a single sector using AES-XTS mode
func (ec *EncryptionContext) decryptXTSSector(inputData, outputData, tweakValue []byte) error {
	// Encrypt the tweak with cipher2
	encryptedTweak := make([]byte, 16)
	ec.cipher2.Encrypt(encryptedTweak, tweakValue)

	// Process each 16-byte block in the sector
	blockSize := 16
	for offset := 0; offset < len(inputData); offset += blockSize {
		// XOR input block with tweak
		block := make([]byte, blockSize)
		for i := 0; i < blockSize && offset+i < len(inputData); i++ {
			block[i] = inputData[offset+i] ^ encryptedTweak[i]
		}

		// Decrypt the block
		decryptedBlock := make([]byte, blockSize)
		ec.cipher1.Decrypt(decryptedBlock, block)

		// XOR decrypted block with tweak to get output
		for i := 0; i < blockSize && offset+i < len(outputData); i++ {
			outputData[offset+i] = decryptedBlock[i] ^ encryptedTweak[i]
		}

		// Multiply tweak by alpha (x) in GF(2^128) for next block
		multiplyTweakByAlpha(encryptedTweak)
	}

	return nil
}

// multiplyTweakByAlpha multiplies the tweak by alpha in GF(2^128)
// This is used in XTS mode to update the tweak for each block
func multiplyTweakByAlpha(tweak []byte) {
	carry := byte(0)

	// Multiply by x in GF(2^128)
	for i := 0; i < len(tweak); i++ {
		nextCarry := (tweak[i] >> 7) & 1
		tweak[i] = (tweak[i] << 1) | carry
		carry = nextCarry
	}

	// If carry, XOR with reduction polynomial (0x87 for AES-XTS)
	if carry != 0 {
		tweak[0] ^= 0x87
	}
}

// AESKeyUnwrap unwraps data using AES Key Wrap (RFC 3394)
func AESKeyUnwrap(key []byte, keyBitSize int, wrappedData []byte) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("invalid AES key")
	}

	// Validate key bit size
	if keyBitSize != 128 && keyBitSize != 192 && keyBitSize != 256 {
		return nil, fmt.Errorf("invalid AES key length value out of bounds: %d", keyBitSize)
	}

	if wrappedData == nil {
		return nil, fmt.Errorf("invalid wrapped data")
	}

	if len(wrappedData) <= 8 {
		return nil, fmt.Errorf("invalid wrapped data size value too small: %d", len(wrappedData))
	}

	if len(wrappedData)%8 != 0 {
		return nil, fmt.Errorf("invalid wrapped data size value not a multitude of 8: %d", len(wrappedData))
	}

	// Create AES context
	keyByteSize := keyBitSize / 8
	if len(key) < keyByteSize {
		return nil, fmt.Errorf("key size too small for specified bit size")
	}

	aesContext, err := aes.NewCipher(key[:keyByteSize])
	if err != nil {
		return nil, fmt.Errorf("unable to initialize AES context: %w", err)
	}

	// Allocate unwrapped data buffer (same size as wrapped)
	unwrappedData := make([]byte, len(wrappedData))
	copy(unwrappedData, wrappedData)

	numberOfBlocks := len(wrappedData) / 8

	if DebugOutput {
		fmt.Printf("EncryptionContext.AESKeyUnwrap: number of blocks: %d\n", numberOfBlocks)
		fmt.Printf("EncryptionContext.AESKeyUnwrap: wrapped data:\n")
		PrintData(wrappedData, false)
	}

	// Initialize vectors
	blockData := make([]byte, 16)
	vectorData := make([]byte, 8)

	// Get pointer to initialization vector (first 8 bytes of unwrapped data)
	initializationVector := unwrappedData[0:8]

	// Perform unwrap rounds (6 rounds as per RFC 3394)
	for roundIndex := 5; roundIndex >= 0; roundIndex-- {
		for blockIndex := numberOfBlocks - 1; blockIndex > 0; blockIndex-- {
			blockOffset := blockIndex * 8

			// Calculate t = round_index * (number_of_blocks - 1) + block_index
			t := uint64(roundIndex*(numberOfBlocks-1) + blockIndex)
			binary.BigEndian.PutUint64(vectorData, t)

			// XOR initialization vector with t
			for i := 0; i < 8; i++ {
				vectorData[i] ^= initializationVector[i]
			}

			// Prepare block data: vector_data || unwrapped_data[block_offset]
			copy(blockData[0:8], vectorData)
			copy(blockData[8:16], unwrappedData[blockOffset:blockOffset+8])

			// Decrypt block using AES-ECB
			aesContext.Decrypt(blockData, blockData)

			// Update initialization vector with first 8 bytes of decrypted block
			copy(initializationVector, blockData[0:8])

			// Update unwrapped data with last 8 bytes of decrypted block
			copy(unwrappedData[blockOffset:blockOffset+8], blockData[8:16])
		}
	}

	if DebugOutput {
		fmt.Printf("EncryptionContext.AESKeyUnwrap: unwrapped data:\n")
		PrintData(unwrappedData, false)
	}

	return unwrappedData, nil
}
