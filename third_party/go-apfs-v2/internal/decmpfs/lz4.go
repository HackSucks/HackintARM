package decmpfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lz4"
)

// LZ4 uses 0xff for stored data. Unlike LZFSE, other non-frame prefixes
// are invalid. All 256 leading-byte decisions are kernel-qualified.
func decompressLZ4Range(source io.ReaderAt, size int64, dst []byte) (int, error) {
	if size <= 0 {
		return 0, fmt.Errorf("empty LZ4 compression block")
	}
	var first [1]byte
	n, err := source.ReadAt(first[:], 0)
	if n != 1 {
		return 0, errors.Join(io.ErrUnexpectedEOF, err)
	}
	if err != nil && err != io.EOF {
		return 0, err
	}
	if first[0] != 0xff {
		return lz4.DecompressReader(dst, source, size)
	}
	if size-1 > int64(len(dst)) {
		return 0, lz4.ErrOutputFull
	}
	n, err = source.ReadAt(dst[:size-1], 1)
	if int64(n) != size-1 {
		return n, errors.Join(io.ErrUnexpectedEOF, err)
	}
	if err == io.EOF {
		err = nil
	}
	return n, err
}
func decompressLZ4(src, dst []byte, size *int) error {
	if *size < 0 || *size > len(dst) {
		return fmt.Errorf("invalid LZ4 output capacity")
	}
	n, err := decompressLZ4Range(bytes.NewReader(src), int64(len(src)), dst[:*size])
	if err == nil {
		*size = n
	}
	return err
}
