package decmpfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// Metadata is a stable compression-metadata snapshot supplied by the caller.
// Flags and LogicalSize are the filesystem's observed BSD flags and file size.
// Attribute is com.apple.decmpfs; nil means absent. ResourceForkSize is -1 for
// an absent resource fork, or its nonnegative byte extent. Values remain borrowed.
// Host capture and explicit AppleDouble/image metadata use the same contract.
type Metadata struct {
	Flags            uint32
	LogicalSize      uint64
	Attribute        appledouble.Value
	ResourceForkSize int64
}

// Info describes the fields returned by Apple's compression-metadata query.
// Successful inspection does not establish that the compressed payload can be
// decoded. Unknown types are reported without inventing a storage layout.
type Info struct {
	Type uint32
	// Overhead has the native query's 32-bit arithmetic, including wraparound.
	// It is descriptive metadata, never an allocation or validation bound.
	Overhead    uint32
	StoredSize  uint64
	LogicalSize uint64
	// AttributeExtension preserves bytes 16..23 of a fork-based attribute.
	// No meaning is assigned to these opaque, optional bytes.
	AttributeExtension [8]byte
	// MissingResourceFork distinguishes a missing required fork from zero size.
	// Native queries succeed in this state, leaving storage accounting zero.
	MissingResourceFork bool
}

// Query reports native compression metadata without decoding or retaining the
// payload. It reads at most 24 attribute bytes and never reads resource-fork
// contents. Uncompressed files report the supplied logical size without reading
// attributes. For type 5 the native unknown-size sentinels are preserved.
//
// Callers must exclude concurrent changes and obtain Flags from actual metadata,
// not from a requested flag update: the kernel can clear invalid compression
// flags. Invalid compressed headers and source failures remain errors. Native
// live-file capture and installation are separate operations.
func Query(ctx context.Context, metadata Metadata) (Info, error) {
	var result Info
	if ctx == nil || metadata.ResourceForkSize < -1 {
		return result, fmt.Errorf("invalid compression metadata")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result.LogicalSize = metadata.LogicalSize
	if metadata.Flags&32 == 0 {
		return result, nil
	}
	if metadata.Attribute == nil || metadata.Attribute.Size() < 16 {
		return result, fmt.Errorf("missing or truncated compression attribute")
	}
	size := metadata.Attribute.Size()
	var header [24]byte
	p := header[:min(size, int64(len(header)))]
	n, err := metadata.Attribute.ReadAt(p, 0)
	if err != nil && !(err == io.EOF && n == len(p)) {
		return result, err
	}
	if n != len(p) {
		return result, io.ErrUnexpectedEOF
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if string(header[:4]) != "fpmc" {
		return result, errors.New("invalid compression attribute magic")
	}
	result.Type = binary.LittleEndian.Uint32(header[4:8])
	result.LogicalSize = binary.LittleEndian.Uint64(header[8:16])
	switch result.Type {
	case 3, 7, 9, 11, 13, 15:
		result.Overhead = 16
		result.StoredSize = uint64(size)
	case 4, 8, 10, 12, 14, 16:
		if size >= 24 {
			copy(result.AttributeExtension[:], header[16:24])
		}
		if metadata.ResourceForkSize < 0 {
			result.MissingResourceFork = true
			break
		}
		result.StoredSize = uint64(size) + uint64(metadata.ResourceForkSize)
		// Match the native unsigned addition and 32-bit accounting field.
		blocks := uint32((result.LogicalSize + 65535) >> 16)
		result.Overhead = uint32(size) + 4 + blocks*4
		if result.Type == 4 {
			result.Overhead = uint32(size) + 314 + blocks*8
		}
	case 5:
		result.Overhead = ^uint32(0)
		result.StoredSize = ^uint64(0)
	}
	return result, nil
}
