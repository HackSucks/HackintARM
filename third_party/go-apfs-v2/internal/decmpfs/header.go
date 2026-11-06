package decmpfs

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// HeaderSignature is the magic every com.apple.decmpfs attribute begins with.
var HeaderSignature = [4]byte{'f', 'p', 'm', 'c'}

// HeaderSize is the size of the com.apple.decmpfs header in bytes.
const HeaderSize = 16

// Header is the com.apple.decmpfs attribute header.
//
// Its fields are little-endian regardless of the file system underneath. That
// is unremarkable on APFS, whose structures are little-endian throughout, but
// it is a trap on HFS+, where everything else on disk is big-endian: the
// attribute is an opaque payload that HFS+ never interprets, so it keeps the
// byte order decmpfs itself uses.
type Header struct {
	// CompressionMethod is the raw on-disk decmpfs type, not one of this
	// package's method codes. Pass it to MethodFor.
	CompressionMethod uint32

	// UncompressedDataSize is the size the file presents once decoded. It is
	// the authoritative length: the data fork of a compressed file is empty.
	UncompressedDataSize uint64
}

// ReadData reads the header from data. It reports whether the signature
// matched; a non-matching signature is not an error, because the caller may be
// probing a value that turns out not to be a decmpfs attribute at all.
func (h *Header) ReadData(data []byte) (bool, error) {
	if h == nil {
		return false, fmt.Errorf("invalid compressed data header")
	}

	if data == nil {
		return false, fmt.Errorf("invalid data")
	}

	if len(data) < HeaderSize {
		return false, fmt.Errorf("invalid data size: expected at least %d bytes, got %d", HeaderSize, len(data))
	}

	if int64(len(data)) > common.Int32Max {
		return false, fmt.Errorf("invalid data size value out of bounds")
	}

	if !bytes.Equal(data[0:4], HeaderSignature[:]) {
		return false, nil
	}

	h.CompressionMethod = binary.LittleEndian.Uint32(data[4:8])
	h.UncompressedDataSize = binary.LittleEndian.Uint64(data[8:16])

	return true, nil
}

// ParseHeader parses a com.apple.decmpfs header. It returns nil with no error
// when the signature does not match.
func ParseHeader(data []byte) (*Header, error) {
	header := &Header{}

	match, err := header.ReadData(data)
	if err != nil {
		return nil, fmt.Errorf("unable to read compressed data header: %w", err)
	}

	if !match {
		return nil, nil
	}

	return header, nil
}
