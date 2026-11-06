package apfs

import (
	"fmt"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

// ExtendedAttribute represents an APFS extended attribute
type ExtendedAttribute struct {
	// IOHandle is the I/O handle
	IOHandle *IOHandle

	// FileHandle is the file I/O handle
	FileHandle io.ReaderAt

	// EncryptionContext is the encryption context
	EncryptionContext *EncryptionContext

	// FileSystemBTree is the file system B-tree
	FileSystemBTree *FileSystemBTree

	// Identifier is the file system identifier
	Identifier uint64

	// AttributeValues contains the attribute values
	AttributeValues *AttributeValues

	// XID is the transaction identifier
	XID uint64

	// DataStream is the data stream (lazily initialized)
	DataStream *DataStream

	// currentOffset tracks the current read position
	currentOffset int64
}

// NewExtendedAttribute creates a new extended attribute
func NewExtendedAttribute(
	ioHandle *IOHandle,
	reader io.ReaderAt,
	encryptionContext *EncryptionContext,
	fileSystemBTree *FileSystemBTree,
	attributeValues *AttributeValues,
	xid uint64,
) (*ExtendedAttribute, error) {
	if attributeValues == nil {
		return nil, fmt.Errorf("invalid attribute values")
	}

	return &ExtendedAttribute{
		IOHandle:          ioHandle,
		FileHandle:        reader,
		EncryptionContext: encryptionContext,
		FileSystemBTree:   fileSystemBTree,
		AttributeValues:   attributeValues,
		XID:               xid,
		currentOffset:     0,
	}, nil
}

// getDataStream retrieves the data stream (lazy initialization)
func (ea *ExtendedAttribute) getDataStream() error {
	if ea.DataStream != nil {
		return nil
	}

	// Get data stream from attribute values
	dataStream, err := ea.AttributeValues.DataStream(
		ea.IOHandle,
		ea.FileHandle,
		ea.EncryptionContext,
		ea.FileSystemBTree,
		ea.XID,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve attribute value data stream: %w", err)
	}

	ea.DataStream = dataStream
	return nil
}

// UTF8NameSize retrieves the size of the UTF-8 encoded name
// The returned size includes the end-of-string character
func (ea *ExtendedAttribute) UTF8NameSize() (int, error) {
	if ea == nil {
		return 0, fmt.Errorf("invalid extended attribute")
	}

	if ea.AttributeValues == nil {
		return 0, fmt.Errorf("invalid attribute values")
	}

	// Return size + 1 for null terminator to match C API behavior
	return len(ea.AttributeValues.Name) + 1, nil
}

// UTF8Name retrieves the UTF-8 encoded name
func (ea *ExtendedAttribute) UTF8Name() (string, error) {
	if ea == nil {
		return "", fmt.Errorf("invalid extended attribute")
	}

	if ea.AttributeValues == nil {
		return "", fmt.Errorf("invalid attribute values")
	}

	return ea.AttributeValues.NameString(), nil
}

// UTF16NameSize retrieves the size of the UTF-16 encoded name
// The returned size includes the end-of-string character
func (ea *ExtendedAttribute) UTF16NameSize() (int, error) {
	if ea == nil {
		return 0, fmt.Errorf("invalid extended attribute")
	}

	if ea.AttributeValues == nil {
		return 0, fmt.Errorf("invalid attribute values")
	}

	// Count the UTF-16 code units needed
	utf16Count := 0
	nameBytes := ea.AttributeValues.Name
	for len(nameBytes) > 0 {
		r, size := utf8.DecodeRune(nameBytes)
		if r == utf8.RuneError {
			return 0, fmt.Errorf("invalid UTF-8 sequence")
		}
		if r <= 0xFFFF {
			utf16Count++
		} else {
			utf16Count += 2 // Surrogate pair
		}
		nameBytes = nameBytes[size:]
	}

	// Add 1 for null terminator
	return utf16Count + 1, nil
}

// UTF16Name retrieves the UTF-16 encoded name
func (ea *ExtendedAttribute) UTF16Name() ([]uint16, error) {
	if ea == nil {
		return nil, fmt.Errorf("invalid extended attribute")
	}

	if ea.AttributeValues == nil {
		return nil, fmt.Errorf("invalid attribute values")
	}

	if ea.AttributeValues.Name == nil {
		return nil, nil
	}

	// Convert UTF-8 to UTF-16
	runes := []rune(string(ea.AttributeValues.Name))
	utf16Encoded := utf16.Encode(runes)

	return utf16Encoded, nil
}

// Read reads data at the current offset into a buffer
func (ea *ExtendedAttribute) Read(buffer []byte) (int, error) {
	if ea == nil {
		return 0, fmt.Errorf("invalid extended attribute")
	}

	// Ensure data stream is initialized
	if ea.DataStream == nil {
		if err := ea.getDataStream(); err != nil {
			return 0, fmt.Errorf("unable to determine data stream: %w", err)
		}
	}

	if ea.DataStream == nil {
		return 0, io.EOF
	}

	// Stop at the end of the attribute's value. Without this the reader relies
	// on the underlying stream to report io.EOF, and a stream that instead
	// returns (0, nil) past its end turns any io.Reader loop over this — such
	// as io.ReadAll — into an infinite one.
	size := ea.DataStream.Size()
	if ea.currentOffset >= int64(size) {
		return 0, io.EOF
	}
	if remaining := int64(size) - ea.currentOffset; remaining < int64(len(buffer)) {
		buffer = buffer[:remaining]
	}

	// Read from data stream at current offset
	n, err := ea.DataStream.ReadAt(buffer, ea.currentOffset)
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("unable to read buffer from data stream: %w", err)
	}

	// Update current offset
	ea.currentOffset += int64(n)

	// A short read that consumed the rest of the value is the end, whatever the
	// underlying stream chose to report.
	if err == nil && ea.currentOffset >= int64(size) && n == 0 {
		return 0, io.EOF
	}

	return n, err
}

// ReadAt reads data at a specific offset
func (ea *ExtendedAttribute) ReadAt(buffer []byte, offset int64) (int, error) {
	if ea == nil {
		return 0, fmt.Errorf("invalid extended attribute")
	}

	// Ensure data stream is initialized
	if ea.DataStream == nil {
		if err := ea.getDataStream(); err != nil {
			return 0, fmt.Errorf("unable to determine data stream: %w", err)
		}
	}

	if ea.DataStream == nil {
		return 0, io.EOF
	}

	// Read from data stream at specified offset
	n, err := ea.DataStream.ReadAt(buffer, offset)
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("unable to read buffer at offset from data stream: %w", err)
	}

	return n, err
}

// Seek seeks to a certain offset
func (ea *ExtendedAttribute) Seek(offset int64, whence int) (int64, error) {
	if ea == nil {
		return 0, fmt.Errorf("invalid extended attribute")
	}

	// Ensure data stream is initialized
	if ea.DataStream == nil {
		if err := ea.getDataStream(); err != nil {
			return 0, fmt.Errorf("unable to determine data stream: %w", err)
		}
	}

	if ea.DataStream == nil {
		return 0, fmt.Errorf("no data stream available")
	}

	// Get the data stream size for calculations
	size, err := ea.Size()
	if err != nil {
		return 0, fmt.Errorf("unable to get data stream size: %w", err)
	}

	// Calculate new offset based on whence
	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = ea.currentOffset + offset
	case io.SeekEnd:
		newOffset = int64(size) + offset
	default:
		return 0, fmt.Errorf("invalid whence value: %d", whence)
	}

	// Validate new offset
	if newOffset < 0 {
		return 0, fmt.Errorf("invalid offset value out of bounds")
	}

	ea.currentOffset = newOffset
	return newOffset, nil
}

// Offset retrieves the current offset
func (ea *ExtendedAttribute) Offset() (int64, error) {
	if ea == nil {
		return 0, fmt.Errorf("invalid extended attribute")
	}

	return ea.currentOffset, nil
}

// Size retrieves the size
func (ea *ExtendedAttribute) Size() (uint64, error) {
	if ea == nil {
		return 0, fmt.Errorf("invalid extended attribute")
	}

	// Ensure data stream is initialized
	if ea.DataStream == nil {
		if err := ea.getDataStream(); err != nil {
			return 0, fmt.Errorf("unable to determine data stream: %w", err)
		}
	}

	if ea.DataStream == nil {
		// No data stream means no data
		return 0, nil
	}

	return ea.DataStream.Size(), nil
}

// NumberOfExtents retrieves the number of extents
func (ea *ExtendedAttribute) NumberOfExtents() (int, error) {
	if ea == nil {
		return 0, fmt.Errorf("invalid extended attribute")
	}

	if ea.AttributeValues == nil {
		return 0, fmt.Errorf("invalid attribute values")
	}

	// Get number of extents from attribute values
	return ea.AttributeValues.NumberOfExtents(), nil
}

// ExtentByIndex retrieves an extent by index
func (ea *ExtendedAttribute) ExtentByIndex(index int) (offset int64, size uint64, flags uint32, err error) {
	if ea == nil {
		return 0, 0, 0, fmt.Errorf("invalid extended attribute")
	}

	if ea.AttributeValues == nil {
		return 0, 0, 0, fmt.Errorf("invalid attribute values")
	}

	// Get extent from attribute values
	extent, err := ea.AttributeValues.ExtentByIndex(index)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("unable to retrieve extent %d: %w", index, err)
	}

	if extent == nil {
		return 0, 0, 0, fmt.Errorf("invalid extent")
	}

	// Calculate physical offset (physical block number * block size)
	// Block size is typically 4096 bytes
	physicalOffset := int64(extent.PhysicalBlockNumber * 4096)

	// Data size is already in bytes
	dataSize := extent.DataSize

	// Flags are in the upper 8 bits of the original DataSizeAndFlags
	// Since we don't store the flags separately, we return 0 for now
	// In the C library, flags would come from the data_size_and_flags field
	extentFlags := uint32(0)

	return physicalOffset, dataSize, extentFlags, nil
}
