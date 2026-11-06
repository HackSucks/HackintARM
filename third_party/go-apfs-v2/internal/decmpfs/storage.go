package decmpfs

import (
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lzbitmap"
)

// decompressStorage handles Apple's raw storage and LZBITMAP chunk payloads.
// Type1 has no marker; type9/10 uses 0xcc; type13/14 uses 0xff only for a
// stored chunk, otherwise a complete ZBM stream. Native fixtures pin both forms.
func decompressStorage(src []byte, method int, dst []byte, size *int) error {
	if *size < 0 || *size > len(dst) {
		return fmt.Errorf("invalid output size %d", *size)
	}
	switch method {
	case MethodRawMarked:
		if len(src) == 0 || src[0] != 0xcc {
			return fmt.Errorf("invalid raw decmpfs marker")
		}
		src = src[1:]
	case MethodLZBITMAP:
		if len(src) == 0 {
			return fmt.Errorf("empty LZBITMAP chunk")
		}
		if src[0] == 0xff {
			src = src[1:]
		} else {
			var err error
			src, err = lzbitmap.DecompressLimit(src, *size)
			if err != nil {
				return fmt.Errorf("invalid LZBITMAP chunk: %w", err)
			}
		}
	}
	if len(src) > *size {
		return fmt.Errorf("decoded storage exceeds output capacity")
	}
	*size = copy(dst, src)
	return nil
}

// Apple's built-in type1 validator requires an exact header/payload size match.
func validateRawSource(source Source, size uint64) error {
	if source.Size() > MaxAttributeSize || size > MaxAttributeSize-HeaderSize || source.Size() != size+HeaderSize {
		return fmt.Errorf("invalid type1 storage size")
	}
	var prefix [HeaderSize]byte
	n, err := source.ReadAt(prefix[:], 0)
	if n != HeaderSize {
		return io.ErrUnexpectedEOF
	}
	if err != nil && err != io.EOF {
		return err
	}
	header, err := ParseHeader(prefix[:])
	if err != nil || header == nil || header.CompressionMethod != 1 || header.UncompressedDataSize != size {
		return fmt.Errorf("invalid type1 header")
	}
	return nil
}
