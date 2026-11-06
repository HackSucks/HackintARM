// Transparent compression: reading a file whose content is stored compressed
// rather than in its data fork.
//
// A compressed file carries the UF_COMPRESSED flag, an empty data fork, and a
// com.apple.decmpfs attribute whose 16-byte header names the compression type
// and the size the file presents. The compressed bytes live either immediately
// after that header, for a small file, or in the file's resource fork, chunked
// into 64 KiB blocks.
//
// None of that is specific to HFS+ -- APFS inherited it unchanged -- so the
// decoding lives in internal/decmpfs and this file only supplies the two things
// that differ: where the attribute comes from, and where the resource fork is.
package hfsplus

import (
	"bytes"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
)

// decmpfsAttrName is the attribute carrying the compression header.
const decmpfsAttrName = "com.apple.decmpfs"

// fileReader is the random-access view of a file's content: the data fork for
// an ordinary file, and a decompressing reader for a compressed one.
type fileReader interface {
	io.ReaderAt

	// Size is the length of the content the file presents, which for a
	// compressed file is its decompressed size.
	Size() int64
}

// decmpfsSource adapts a byte range to the Source interface internal/decmpfs
// reads compressed data through.
type decmpfsSource struct {
	io.ReaderAt
	size uint64
}

func (s decmpfsSource) Size() uint64 { return s.size }

// decmpfsReader builds the decompressing reader for a file carrying
// UF_COMPRESSED.
func (v *Volume) decmpfsReader(e *entry) (fileReader, error) {
	fileID, ok := entryFileID(e)
	if !ok {
		return nil, fmt.Errorf("entry has no catalog record")
	}

	if err := v.loadAttributes(); err != nil {
		return nil, err
	}
	rec := v.attributes[attrKey{fileID: fileID, name: decmpfsAttrName}]
	if rec == nil {
		// The flag and the attribute must agree. Saying so beats a generic
		// "not found": it names an inconsistency in the volume rather than
		// implying the file is simply unreadable.
		return nil, fmt.Errorf("file %d has UF_COMPRESSED set but no %s attribute", fileID, decmpfsAttrName)
	}
	attrValue, err := v.attributeValue(fileID, decmpfsAttrName)
	if err != nil {
		return nil, err
	}

	header, err := decmpfs.ParseHeader(attrValue)
	if err != nil {
		return nil, err
	}
	if header == nil {
		return nil, fmt.Errorf("the %s attribute of file %d does not carry the expected header", decmpfsAttrName, fileID)
	}

	// An empty file needs no block table, and asking for one would fail.
	if header.UncompressedDataSize == 0 {
		return emptyReader{}, nil
	}

	method, err := decmpfs.MethodFor(header.CompressionMethod)
	if err != nil {
		return nil, err
	}

	var source decmpfs.Source
	if len(attrValue) > decmpfs.HeaderSize {
		// Stored inline. The whole attribute value goes through, header
		// included: the block-offset loader identifies inline storage by the
		// magic at offset zero, and stripping the header silently sends it
		// down the resource-fork branch instead.
		if err := decmpfs.CheckInline(attrValue); err != nil {
			return nil, err
		}
		source = decmpfsSource{ReaderAt: bytes.NewReader(attrValue), size: uint64(len(attrValue))}
	} else {
		fork, err := v.resourceForkReader(e)
		if err != nil {
			return nil, fmt.Errorf("compressed file %d: %w", fileID, err)
		}
		if fork.Size() == 0 {
			return nil, fmt.Errorf("compressed file %d stores its data in a resource fork, but the fork is empty", fileID)
		}
		source = decmpfsSource{ReaderAt: fork, size: uint64(fork.Size())}
	}

	// A handle carries a mutable current-block cache and two 64 KiB buffers,
	// and is not safe for concurrent use, so each open gets its own.
	handle, err := decmpfs.NewHandle(source, header.UncompressedDataSize, method)
	if err != nil {
		return nil, err
	}

	return &decmpfsReaderAt{handle: handle, size: int64(header.UncompressedDataSize)}, nil
}

// logicalSize is the size a file presents: its data fork's length, or for a
// compressed file the size named in its decmpfs header. A compressed file's
// data fork is empty, so without this it would list as zero bytes.
//
// A failure here is swallowed deliberately. fs.DirEntry.Info has no useful
// error path, so a file whose compression metadata is broken lists at its data
// fork's size and then fails loudly on read, where the caller can act on it.
func (v *Volume) logicalSize(e *entry) int64 {
	if e.file == nil {
		return 0
	}
	if e.file.BSDInfo.OwnerFlags&ufCompressed == 0 {
		return int64(e.file.DataFork.LogicalSize)
	}
	if size, ok := v.decmpfsSize(e.file.FileID); ok {
		return size
	}
	return int64(e.file.DataFork.LogicalSize)
}

// decmpfsSize returns the size a compressed file presents, from its decmpfs
// header.
func (v *Volume) decmpfsSize(fileID CatalogNodeID) (int64, bool) {
	if err := v.loadAttributes(); err != nil {
		return 0, false
	}
	value, err := v.attributeValue(fileID, decmpfsAttrName)
	if err != nil {
		return 0, false
	}
	header, err := decmpfs.ParseHeader(value)
	if err != nil || header == nil {
		return 0, false
	}
	return int64(header.UncompressedDataSize), true
}

// decmpfsReaderAt presents a compressed file's decompressed content.
//
// The handle underneath is a sequential decoder with a seek, so ReadAt drives
// it rather than being driven by it, and reads are not safe to issue
// concurrently against one open file.
type decmpfsReaderAt struct {
	handle *decmpfs.Handle
	size   int64
}

func (r *decmpfsReaderAt) Size() int64 { return r.size }

func (r *decmpfsReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset %d", off)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}

	// Clamp to the file's size so a short final read reports io.EOF rather
	// than running the decoder past the end, matching forkReader.
	want := int64(len(p))
	if want > r.size-off {
		want = r.size - off
	}

	if _, err := r.handle.SeekSegmentOffset(0, off); err != nil {
		return 0, err
	}

	total := 0
	for total < int(want) {
		n, err := r.handle.ReadSegmentData(0, p[total:want])
		total += n
		if err != nil {
			if err == io.EOF {
				break
			}
			return total, err
		}
		if n == 0 {
			break
		}
	}

	if total < len(p) {
		return total, io.EOF
	}
	return total, nil
}

// emptyReader is the content of a compressed file that decompresses to nothing.
type emptyReader struct{}

func (emptyReader) Size() int64 { return 0 }

func (emptyReader) ReadAt([]byte, int64) (int, error) { return 0, io.EOF }
