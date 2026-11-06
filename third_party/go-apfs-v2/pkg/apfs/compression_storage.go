package apfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
)

// compressionAttribute opens the complete attribute, including extent-backed
// values. Inline decmpfs storage need not be embedded in the APFS xattr record.
// Only the fixed header is read here; payloads remain bounded stream sources.
func (fe *FileEntry) compressionAttribute() (*DataStream, *CompressedDataHeader, error) {
	if err := fe.getExtendedAttributes(); err != nil {
		return nil, nil, err
	}
	source, err := fe.attributeStream(fe.CompressedDataAttributeValues)
	if err != nil {
		return nil, nil, err
	}
	header, err := compressionStreamHeader(source)
	return source, header, err
}

func (fe *FileEntry) attributeStream(value *AttributeValues) (*DataStream, error) {
	if value == nil {
		return nil, fmt.Errorf("missing compressed storage: %w", fs.ErrInvalid)
	}
	source, err := value.DataStream(fe.IOHandle, fe.FileHandle, fe.EncryptionContext, fe.FileSystemBTree, fe.XID)
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, fmt.Errorf("invalid compressed storage flags: %w", fs.ErrInvalid)
	}
	return source, nil
}

func compressionStreamHeader(source *DataStream) (*CompressedDataHeader, error) {
	if source.Size() < decmpfs.HeaderSize || source.Size() > decmpfs.MaxAttributeSize {
		return nil, fs.ErrInvalid
	}
	var prefix [decmpfs.HeaderSize]byte
	n, err := source.ReadAt(prefix[:], 0)
	if n != len(prefix) {
		return nil, errors.Join(io.ErrUnexpectedEOF, err)
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	header, err := ParseCompressedDataHeader(prefix[:])
	if err != nil || header == nil {
		return nil, errors.Join(fs.ErrInvalid, err)
	}
	if header.UncompressedDataSize > math.MaxInt64 {
		return nil, fs.ErrInvalid
	}
	if _, err = internalCompressionMethod(header.CompressionMethod); err != nil {
		return nil, err
	}
	return header, nil
}

func (fe *FileEntry) compressedStream() (*DataStream, error) {
	source, header, err := fe.compressionAttribute()
	if err != nil {
		return nil, err
	}
	fe.CompressedDataHeader = header
	if decmpfs.StoresDataInResourceFork(header.CompressionMethod) {
		source, err = fe.attributeStream(fe.ResourceForkAttributeValues)
		if err != nil {
			return nil, err
		}
	}
	// The header query already validated the compression method.
	method, _ := internalCompressionMethod(header.CompressionMethod)
	stream, err := NewDataStreamFromCompressedDataStream(source, header.UncompressedDataSize, method)
	if err != nil {
		return nil, err
	}
	stream.readerAt.(*compressedDataReader).SetFileHandle(fe.FileHandle)
	return stream, nil
}
