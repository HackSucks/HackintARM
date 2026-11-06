package apfs

import (
	"bytes"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// DataStream represents a data stream abstraction for APFS data
// This wraps various data sources (embedded data, file extents, compressed data)
type DataStream struct {
	// The underlying reader
	reader io.Reader

	// The underlying reader-at (for random access)
	readerAt io.ReaderAt

	// The size of the data stream
	size uint64

	// The current read offset
	offset int64
}

// NewDataStreamFromData creates a data stream from embedded byte data
func NewDataStreamFromData(data []byte) (*DataStream, error) {
	if len(data) > common.Int32Max {
		return nil, fmt.Errorf("invalid data size value exceeds maximum")
	}

	// Use bytes.NewReader for simple in-memory data
	// This is equivalent to using BufferDataHandle but more idiomatic in Go
	reader := bytes.NewReader(data)
	return &DataStream{
		reader:   reader,
		readerAt: reader,
		size:     uint64(len(data)),
		offset:   0,
	}, nil
}

// NewDataStreamFromFileExtents creates a data stream from file extents
// Uses DataBlockDataHandle to read blocks from disk with encryption support
func NewDataStreamFromFileExtents(
	ioHandle *IOHandle,
	encryptionContext *EncryptionContext,
	fileExtents []*FileExtent,
	size uint64,
	isSparse bool,
) (*DataStream, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	// Create data block data handle
	dataHandle, err := NewDataBlockDataHandle(ioHandle, encryptionContext, fileExtents, isSparse)
	if err != nil {
		return nil, fmt.Errorf("unable to create data block data handle: %w", err)
	}

	// Use the actual file size from the inode, not the allocated extent size
	// File extents are block-aligned, so they're always >= actual file size
	// The dataHandle.DataSize is the sum of allocated extent sizes (block-aligned)
	// We want to use the actual file size from the inode for reading
	dataHandle.DataSize = size

	// Create a reader wrapper around the data handle
	// Note: reader needs to be set by the caller via SetFileHandle
	reader := &dataBlockReader{
		dataHandle: dataHandle,
	}

	return &DataStream{
		reader:   reader,
		readerAt: reader,
		size:     dataHandle.DataSize,
		offset:   0,
	}, nil
}

// NewDataStreamFromCompressedDataStream creates a data stream from compressed data
// Uses CompressedDataHandle to decompress data on-the-fly
func NewDataStreamFromCompressedDataStream(
	compressedDataStream *DataStream,
	uncompressedSize uint64,
	compressionMethod int,
) (*DataStream, error) {
	if compressedDataStream == nil {
		return nil, fmt.Errorf("invalid compressed data stream")
	}

	// Create compressed data handle
	dataHandle, err := NewCompressedDataHandle(compressedDataStream, uncompressedSize, compressionMethod)
	if err != nil {
		return nil, fmt.Errorf("unable to create compressed data handle: %w", err)
	}

	// Create a reader wrapper around the compressed data handle
	reader := &compressedDataReader{
		dataHandle: dataHandle,
	}

	return &DataStream{
		reader:   reader,
		readerAt: reader,
		size:     uncompressedSize,
		offset:   0,
	}, nil
}

// Read implements io.Reader interface
func (ds *DataStream) Read(p []byte) (n int, err error) {
	if ds.reader == nil {
		return 0, fmt.Errorf("data stream reader not initialized")
	}

	n, err = ds.reader.Read(p)
	if err == nil {
		ds.offset += int64(n)
	}
	return n, err
}

// ReadAt implements io.ReaderAt interface
func (ds *DataStream) ReadAt(p []byte, off int64) (n int, err error) {
	if ds.readerAt == nil {
		return 0, fmt.Errorf("data stream reader-at not initialized")
	}

	return ds.readerAt.ReadAt(p, off)
}

// Seek implements io.Seeker interface
func (ds *DataStream) Seek(offset int64, whence int) (int64, error) {
	seeker, ok := ds.reader.(io.Seeker)
	if !ok {
		return 0, fmt.Errorf("data stream does not support seeking")
	}

	newOffset, err := seeker.Seek(offset, whence)
	if err == nil {
		ds.offset = newOffset
	}
	return newOffset, err
}

// Size returns the size of the data stream
func (ds *DataStream) Size() uint64 {
	return ds.size
}

// Close closes the data stream
func (ds *DataStream) Close() error {
	if closer, ok := ds.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// dataBlockReader wraps a DataBlockDataHandle to implement io.Reader and io.ReaderAt
type dataBlockReader struct {
	dataHandle *DataBlockDataHandle
	reader     io.ReaderAt // Set when first used
}

// Read implements io.Reader interface
func (r *dataBlockReader) Read(p []byte) (n int, err error) {
	if r.dataHandle == nil {
		return 0, fmt.Errorf("invalid data block reader - missing data handle")
	}

	// Note: This requires a file handle to be available
	// In practice, this would need to be set externally or passed through context
	if r.reader == nil {
		return 0, fmt.Errorf("file handle not set for data block reader")
	}

	n, err = r.dataHandle.ReadSegmentData(
		r.reader,
		0, // segment index (unused)
		0, // segment file index (unused)
		p,
		len(p),
		0, // segment flags (unused)
		0, // read flags (unused)
	)

	return n, err
}

// ReadAt implements io.ReaderAt interface
func (r *dataBlockReader) ReadAt(p []byte, off int64) (n int, err error) {
	if r.dataHandle == nil {
		return 0, fmt.Errorf("invalid data block reader - missing data handle")
	}

	if r.reader == nil {
		return 0, fmt.Errorf("file handle not set for data block reader")
	}

	// Save current offset
	savedOffset := r.dataHandle.CurrentOffset

	// Seek to the requested offset
	_, err = r.dataHandle.SeekSegmentOffset(r.reader, 0, 0, off)
	if err != nil {
		return 0, fmt.Errorf("unable to seek to offset %d: %w", off, err)
	}

	// Read the data
	n, err = r.dataHandle.ReadSegmentData(
		r.reader,
		0, // segment index (unused)
		0, // segment file index (unused)
		p,
		len(p),
		0, // segment flags (unused)
		0, // read flags (unused)
	)

	// Restore original offset
	r.dataHandle.CurrentOffset = savedOffset

	return n, err
}

// Seek implements io.Seeker interface
func (r *dataBlockReader) Seek(offset int64, whence int) (int64, error) {
	if r.dataHandle == nil {
		return 0, fmt.Errorf("invalid data block reader - missing data handle")
	}

	if r.reader == nil {
		return 0, fmt.Errorf("file handle not set for data block reader")
	}

	var newOffset int64

	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = r.dataHandle.CurrentOffset + offset
	case io.SeekEnd:
		newOffset = int64(r.dataHandle.DataSize) + offset
	default:
		return 0, fmt.Errorf("invalid whence value: %d", whence)
	}

	if newOffset < 0 {
		return 0, fmt.Errorf("negative seek position: %d", newOffset)
	}

	return r.dataHandle.SeekSegmentOffset(r.reader, 0, 0, newOffset)
}

// Close implements io.Closer interface
func (r *dataBlockReader) Close() error {
	if r.dataHandle != nil {
		return r.dataHandle.Close()
	}
	return nil
}

// SetFileHandle sets the file handle for the reader
func (r *dataBlockReader) SetFileHandle(reader io.ReaderAt) {
	r.reader = reader
}

// compressedDataReader wraps a CompressedDataHandle to implement io.Reader and io.ReaderAt
type compressedDataReader struct {
	dataHandle *CompressedDataHandle
	reader     io.ReaderAt // Set when first used
}

// Read implements io.Reader interface
func (r *compressedDataReader) Read(p []byte) (n int, err error) {
	if r.dataHandle == nil {
		return 0, fmt.Errorf("invalid compressed data reader - missing data handle")
	}

	if r.reader == nil {
		return 0, fmt.Errorf("file handle not set for compressed data reader")
	}

	n, err = r.dataHandle.ReadSegmentData(
		0, // segment index
		p,
	)

	return n, err
}

// ReadAt implements io.ReaderAt interface
func (r *compressedDataReader) ReadAt(p []byte, off int64) (n int, err error) {
	if r.dataHandle == nil {
		return 0, fmt.Errorf("invalid compressed data reader - missing data handle")
	}

	if r.reader == nil {
		return 0, fmt.Errorf("file handle not set for compressed data reader")
	}

	// Save current offset
	savedOffset := r.dataHandle.CurrentSegmentOffset

	// Seek to the requested offset
	_, err = r.dataHandle.SeekSegmentOffset(0, off)
	if err != nil {
		return 0, fmt.Errorf("unable to seek to offset %d: %w", off, err)
	}

	// Read the data
	n, err = r.dataHandle.ReadSegmentData(
		0, // segment index
		p,
	)

	// Restore original offset
	r.dataHandle.CurrentSegmentOffset = savedOffset

	return n, err
}

// Seek implements io.Seeker interface
func (r *compressedDataReader) Seek(offset int64, whence int) (int64, error) {
	if r.dataHandle == nil {
		return 0, fmt.Errorf("invalid compressed data reader - missing data handle")
	}

	if r.reader == nil {
		return 0, fmt.Errorf("file handle not set for compressed data reader")
	}

	var newOffset int64

	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = r.dataHandle.CurrentSegmentOffset + offset
	case io.SeekEnd:
		newOffset = int64(r.dataHandle.UncompressedDataSize) + offset
	default:
		return 0, fmt.Errorf("invalid whence value: %d", whence)
	}

	if newOffset < 0 {
		return 0, fmt.Errorf("negative seek position: %d", newOffset)
	}

	return r.dataHandle.SeekSegmentOffset(0, newOffset)
}

// Close implements io.Closer interface
func (r *compressedDataReader) Close() error {
	if r.dataHandle != nil {
		return r.dataHandle.Close()
	}
	return nil
}

// SetFileHandle sets the file handle for the reader
func (r *compressedDataReader) SetFileHandle(reader io.ReaderAt) {
	r.reader = reader
}
