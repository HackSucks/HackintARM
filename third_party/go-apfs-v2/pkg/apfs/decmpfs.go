package apfs

import (
	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
)

// decmpfs decoding moved to internal/decmpfs when the HFS+ reader came to need
// it too: transparent compression is a property of the file rather than of the
// file system, so the header, the block table and the codecs are identical on
// both. The names below are kept as aliases so this package's published surface
// is unchanged.

// Compression method constants.
const (
	CompressionMethodNone      = decmpfs.MethodNone
	CompressionMethodDeflate   = decmpfs.MethodDeflate
	CompressionMethodLZFSE     = decmpfs.MethodLZFSE
	CompressionMethodLZVN      = decmpfs.MethodLZVN
	CompressionMethodRawMarked = decmpfs.MethodRawMarked
	CompressionMethodLZBITMAP  = decmpfs.MethodLZBITMAP
	CompressionMethodLZ4       = decmpfs.MethodLZ4

	// Deprecated: decmpfs type 5 marks de-duplication within the generation
	// store rather than a compression method, so nothing maps to this and no
	// handle can carry it. It was previously decoded as sparse and answered
	// with zeros, which silently returned the wrong contents.
	CompressionMethodUnknown5 = decmpfs.MethodUnknown5
)

// CompressedDataHandleBlockSize is the uncompressed size of one decmpfs chunk.
// It is unrelated to the container block size.
const CompressedDataHandleBlockSize = decmpfs.BlockSize

// CompressedDataHeaderSize is the size of the com.apple.decmpfs header in bytes.
const CompressedDataHeaderSize = decmpfs.HeaderSize

// CompressedDataHeaderSignature is the magic every com.apple.decmpfs attribute
// begins with.
var CompressedDataHeaderSignature = decmpfs.HeaderSignature

type (
	// CompressedDataHandle decodes one decmpfs stream.
	CompressedDataHandle = decmpfs.Handle

	// CompressedDataHeader is the com.apple.decmpfs attribute header.
	CompressedDataHeader = decmpfs.Header

	// CompressedDataSource is the compressed byte range a decmpfs stream lives
	// in. *DataStream satisfies it.
	CompressedDataSource = decmpfs.Source
)

// A *DataStream is the APFS-side source of compressed bytes; the assertion
// keeps that contract checked at compile time rather than at the call.
var _ CompressedDataSource = (*DataStream)(nil)

// DecompressData decompresses one decmpfs chunk with the given method.
func DecompressData(compressedData []byte, compressionMethod int, uncompressedData []byte, uncompressedDataSize *int) error {
	return decmpfs.Decompress(compressedData, compressionMethod, uncompressedData, uncompressedDataSize)
}

// NewCompressedDataHandle creates a decoder for a compressed stream.
func NewCompressedDataHandle(compressedDataStream *DataStream, uncompressedDataSize uint64, compressionMethod int) (*CompressedDataHandle, error) {
	return decmpfs.NewHandle(compressedDataStream, uncompressedDataSize, compressionMethod)
}

// ParseCompressedDataHeader parses a com.apple.decmpfs header. It returns nil
// with no error when the signature does not match.
func ParseCompressedDataHeader(data []byte) (*CompressedDataHeader, error) {
	return decmpfs.ParseHeader(data)
}
