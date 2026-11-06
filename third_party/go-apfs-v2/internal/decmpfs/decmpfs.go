// Package decmpfs decodes Apple's transparent file compression.
//
// decmpfs is a property of the file, not of the file system: a
// com.apple.decmpfs extended attribute holds a 16-byte header naming the
// compression type and the uncompressed size, and the compressed bytes live
// either immediately after that header ("inline") or in the file's resource
// fork, chunked into 64 KiB blocks. HFS+ introduced it and APFS carries it
// unchanged, so both readers need the same decoder and neither should own it.
//
// The caller supplies a Source — the byte range the compressed data lives in —
// and this package handles the header, the block table and the codecs. What it
// deliberately does not know is how to find either of those things, since that
// is where the two file systems differ.
package decmpfs

import (
	"bytes"
	"fmt"
)

// BlockSize is the uncompressed size of one decmpfs chunk. Every block except
// the last decompresses to exactly this much.
//
// It is unrelated to any file system's block size.
const BlockSize = 65536

// The two extended attributes a compressed file is made of: the header (and,
// for the odd types, the payload) in AttributeName, and the chunked payload for
// the even types in ResourceForkName. They are named here so the readers and
// writers of both file systems agree on the spelling.
const (
	AttributeName    = "com.apple.decmpfs"
	ResourceForkName = "com.apple.ResourceFork"
	// MaxAttributeSize is XNU MAX_DECMPFS_XATTR_SIZE, including the header.
	MaxAttributeSize = 3802
)

// Internal compression method codes. These are this package's own vocabulary,
// not the decmpfs type numbers stored on disk; MethodFor translates. Several
// on-disk types share one method, because whether the data sits inline or in a
// resource fork is decided by where it is read from rather than by how it is
// decoded.
const (
	MethodNone      = 0
	MethodDeflate   = 1
	MethodLZFSE     = 2
	MethodLZVN      = 3
	MethodRawMarked = 4
	MethodLZBITMAP  = 6
	MethodLZ4       = 7

	// MethodUnknown5 is retained only because it is reachable through a
	// deprecated alias in pkg/apfs. Nothing maps to it: see MethodFor.
	MethodUnknown5 = 5
)

// Source is the compressed byte range a decmpfs stream lives in: an APFS data
// stream, or an HFS+ resource fork, or the attribute value itself when the data
// is stored inline.
type Source interface {
	ReadAt(p []byte, off int64) (int, error)

	// Size is the length of the compressed range in bytes.
	Size() uint64
}

// MethodFor maps a raw com.apple.decmpfs type to the internal method code.
//
// The types come in attribute/resource-fork pairs, the odd member of each pair
// storing the data inline in the com.apple.decmpfs attribute and the even
// member storing it in the com.apple.ResourceFork attribute, chunked. The
// numbering is Apple's, from copyfile.c:
//
//	 1       uncompressed, stored inline
//	 3 /  4  zlib
//	 5       de-duplication within the generation store
//	 6       unused
//	 7 /  8  LZVN
//	 9 / 10  uncompressed
//	11 / 12  LZFSE
//	13 / 14  LZBITMAP
//
// The attribute-versus-resource-fork distinction is handled by where the data
// is read from, not by the method code, so each supported pair maps to one
// method.
func MethodFor(decmpfsType uint32) (int, error) {
	switch decmpfsType {
	case 3, 4:
		return MethodDeflate, nil
	case 7, 8:
		return MethodLZVN, nil
	case 11, 12:
		return MethodLZFSE, nil
	case 1:
		return MethodNone, nil
	case 9, 10:
		return MethodRawMarked, nil
	case 13, 14:
		return MethodLZBITMAP, nil

	case 15, 16:
		return MethodLZ4, nil

	case 5:
		// Not a compression type at all: it marks de-duplication within the
		// generation store, and the content is not described by this attribute.
		// This was previously decoded as sparse and answered with zeros, which
		// silently returned the wrong contents for a file that has real data
		// somewhere else. Refusing is the only safe answer.
		return 0, fmt.Errorf("decmpfs type 5 (de-duplication within the generation store) does not describe file content and is not supported")
	default:
		return 0, fmt.Errorf("unsupported decmpfs compression type: %d", decmpfsType)
	}
}

// CheckInline verifies that attrValue is a whole com.apple.decmpfs attribute
// with its header still attached, as inline decoding requires.
//
// The block-offset loader identifies inline storage by finding the header magic
// at offset zero. Handing it the payload with the header stripped hides that
// magic and sends the stream down the resource-fork branch, which misparses the
// first bytes of the compressed data as a block-offset table and produces
// plausible nonsense. Checking here makes that mistake fail loudly instead.
func CheckInline(attrValue []byte) error {
	if len(attrValue) > MaxAttributeSize {
		return fmt.Errorf("decmpfs attribute exceeds native %d-byte limit", MaxAttributeSize)
	}
	if len(attrValue) <= HeaderSize {
		return fmt.Errorf("inline decmpfs attribute is %d bytes: too short to hold a %d-byte header and any data",
			len(attrValue), HeaderSize)
	}
	if !bytes.Equal(attrValue[:4], HeaderSignature[:]) {
		return fmt.Errorf("inline decmpfs data must carry its %q header: the block-offset loader identifies inline storage by that magic at offset zero",
			string(HeaderSignature[:]))
	}
	return nil
}

// StoresDataInResourceFork reports whether an on-disk decmpfs type keeps its
// payload in com.apple.ResourceFork rather than in the attribute itself.
//
// The types come in pairs, the odd member storing inline and the even member
// storing in the fork; see MethodFor.
func StoresDataInResourceFork(decmpfsType uint32) bool {
	return decmpfsType%2 == 0
}

// Validate checks that a com.apple.decmpfs attribute and the file carrying it
// agree, so a writer refuses an inconsistent file rather than producing one a
// checker will reject or a reader will silently misread.
//
// dataForkSize is the length of the file's data fork and resourceFork the
// com.apple.ResourceFork attribute value, nil when the file has none.
func Validate(attrValue []byte, dataForkSize int, resourceFork []byte) error {
	return ValidateLayout(attrValue, uint64(len(attrValue)), uint64(dataForkSize), uint64(len(resourceFork)))
}

// ValidateLayout checks storage shape without allocating an entire attribute or
// resource fork. prefix must contain the attribute's complete header (or all its
// bytes when shorter); attrSize is its full length. It validates the same
// compression methods and structural rules as Validate, not compressed payload
// integrity. Sources must remain immutable between validation and writing.
func ValidateLayout(prefix []byte, attrSize, dataForkSize, resourceForkSize uint64) error {
	if attrSize > MaxAttributeSize {
		return fmt.Errorf("decmpfs attribute exceeds native %d-byte limit", MaxAttributeSize)
	}
	if uint64(len(prefix)) > attrSize || uint64(len(prefix)) < min(attrSize, uint64(HeaderSize)) {
		return fmt.Errorf("decmpfs prefix length %d does not cover attribute header for %d bytes", len(prefix), attrSize)
	}
	header, err := ParseHeader(prefix)
	if err != nil {
		return err
	}
	if header == nil {
		return fmt.Errorf("decmpfs attribute does not begin with the %q header", string(HeaderSignature[:]))
	}
	if _, err := MethodFor(header.CompressionMethod); err != nil {
		return err
	}

	// The content of a compressed file lives in the attribute or the resource
	// fork; the data fork is empty by definition. Bytes there would be a second,
	// contradictory copy, and readers dispatch on the attribute, so they would
	// be the copy nobody reads.
	if dataForkSize != 0 {
		return fmt.Errorf("a decmpfs-compressed file has an empty data fork, but this one has %d bytes of data",
			dataForkSize)
	}
	if header.CompressionMethod == 1 && (header.UncompressedDataSize > ^uint64(0)-HeaderSize || header.UncompressedDataSize+HeaderSize != attrSize) {
		return fmt.Errorf("decmpfs type 1 requires attribute size equal to header plus declared file size")
	}
	if header.CompressionMethod == 1 && header.UncompressedDataSize == 0 {
		return nil
	}

	if StoresDataInResourceFork(header.CompressionMethod) {
		if resourceForkSize == 0 {
			return fmt.Errorf("decmpfs type %d keeps its data in %s, which is absent",
				header.CompressionMethod, ResourceForkName)
		}
		// The attribute is the header alone: the payload is in the fork.
		if attrSize != HeaderSize {
			return fmt.Errorf("decmpfs type %d keeps its data in %s, but the attribute carries %d bytes beyond its %d-byte header",
				header.CompressionMethod, ResourceForkName, attrSize-HeaderSize, HeaderSize)
		}
		return nil
	}

	// Inline compression leaves the catalog resource fork available for
	// independent file metadata; native macOS retains and exposes that fork.
	if attrSize <= HeaderSize {
		return fmt.Errorf("inline decmpfs attribute is %d bytes: too short to hold a %d-byte header and any data", attrSize, HeaderSize)
	}
	return nil
}
