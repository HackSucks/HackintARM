package decmpfs

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lzfse"
)

// Decompress decompresses one decmpfs chunk with the given method, writing into
// uncompressedData and updating uncompressedDataSize to the number of bytes
// produced.
func Decompress(
	compressedData []byte,
	compressionMethod int,
	uncompressedData []byte,
	uncompressedDataSize *int,
) error {
	if compressedData == nil {
		return fmt.Errorf("invalid compressed data buffer")
	}

	if uncompressedData == nil {
		return fmt.Errorf("invalid uncompressed data buffer")
	}

	if uncompressedDataSize == nil {
		return fmt.Errorf("invalid uncompressed data size")
	}

	switch compressionMethod {
	case MethodNone, MethodRawMarked, MethodLZBITMAP:
		return decompressStorage(compressedData, compressionMethod, uncompressedData, uncompressedDataSize)
	case MethodDeflate:
		return decompressDeflate(compressedData, uncompressedData, uncompressedDataSize)

	case MethodLZVN:
		return decompressLZVN(compressedData, uncompressedData, uncompressedDataSize)

	case MethodLZ4:
		return decompressLZ4(compressedData, uncompressedData, uncompressedDataSize)

	case MethodLZFSE:
		return decompressLZFSE(compressedData, uncompressedData, uncompressedDataSize)

	default:
		return fmt.Errorf("unsupported compression method: %d", compressionMethod)
	}
}

// decompressDeflate decompresses DEFLATE/zlib compressed data
// Handles the special case where data prefixed with 0xff is uncompressed
func decompressDeflate(compressedData []byte, uncompressedData []byte, uncompressedDataSize *int) error {
	// Check if data is prefixed with 0xff (indicates uncompressed data)
	if len(compressedData) >= 1 && compressedData[0] == 0xff {
		// Data is uncompressed, just copy it (skip the 0xff prefix)
		if int64(len(compressedData)) > common.Int32Max {
			return fmt.Errorf("invalid compressed data size value exceeds maximum")
		}

		if int64(*uncompressedDataSize) > common.Int32Max {
			return fmt.Errorf("invalid uncompressed data size value exceeds maximum")
		}

		if (len(compressedData) - 1) > *uncompressedDataSize {
			return fmt.Errorf("compressed data size exceeds uncompressed data size")
		}

		*uncompressedDataSize = len(compressedData) - 1
		copy(uncompressedData, compressedData[1:])
		return nil
	}

	// Data is compressed, decompress using zlib
	reader, err := zlib.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return fmt.Errorf("unable to create zlib reader: %w", err)
	}
	defer reader.Close()

	// Read decompressed data
	n, err := io.ReadFull(reader, uncompressedData[:*uncompressedDataSize])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("unable to decompress deflate data: %w", err)
	}

	*uncompressedDataSize = n
	return nil
}

// decompressLZVN decompresses LZVN compressed data
// Handles the special case where data prefixed with 0x06 is uncompressed
func decompressLZVN(compressedData []byte, uncompressedData []byte, uncompressedDataSize *int) error {
	// Check if data is prefixed with 0x06 (indicates uncompressed data)
	if len(compressedData) >= 1 && compressedData[0] == 0x06 {
		// Data is uncompressed, just copy it (skip the 0x06 prefix)
		if int64(len(compressedData)) > common.Int32Max {
			return fmt.Errorf("invalid compressed data size value exceeds maximum")
		}

		if int64(*uncompressedDataSize) > common.Int32Max {
			return fmt.Errorf("invalid uncompressed data size value exceeds maximum")
		}

		if (len(compressedData) - 1) > *uncompressedDataSize {
			return fmt.Errorf("compressed data size exceeds uncompressed data size")
		}

		*uncompressedDataSize = len(compressedData) - 1
		copy(uncompressedData, compressedData[1:])
		return nil
	}

	// Data is compressed, decompress using LZVN (decmpfs stores raw LZVN
	// streams without an lzfse container header)
	decompressed, err := lzfse.DecompressLZVN(compressedData, *uncompressedDataSize)
	if err != nil {
		return fmt.Errorf("unable to decompress LZVN data: %w", err)
	}

	// Copy decompressed data to output buffer
	if len(decompressed) > *uncompressedDataSize {
		return fmt.Errorf("decompressed data size (%d) exceeds buffer size (%d)", len(decompressed), *uncompressedDataSize)
	}

	n := copy(uncompressedData, decompressed)
	*uncompressedDataSize = n
	return nil
}

// lzfseBlockMagicFirstByte is 'b', the first byte of every LZFSE block magic
// ("bvx1", "bvx2", "bvxn", "bvx-"). decmpfs marks a chunk that did not compress
// by storing it raw behind a one-byte prefix, and the reader detects that by
// the *absence* of this magic rather than by any particular prefix value —
// which is what macOS's own implementation does. In practice macOS writes 0xff.
const lzfseBlockMagicFirstByte = 0x62

// decompressLZFSE decompresses one decmpfs LZFSE chunk.
//
// A chunk that does not begin with the LZFSE block magic is stored raw behind a
// one-byte marker. Note this is magic-absence, not a sentinel value, and in
// particular it is not LZVN's 0x06: reusing that here would misread any raw
// chunk whose first byte happened to differ.
func decompressLZFSE(compressedData []byte, uncompressedData []byte, uncompressedDataSize *int) error {
	if len(compressedData) == 0 {
		return fmt.Errorf("invalid compressed data buffer")
	}

	if compressedData[0] != lzfseBlockMagicFirstByte {
		// Stored raw: copy everything after the marker byte.
		if int64(len(compressedData)) > common.Int32Max {
			return fmt.Errorf("invalid compressed data size value exceeds maximum")
		}
		if int64(*uncompressedDataSize) > common.Int32Max {
			return fmt.Errorf("invalid uncompressed data size value exceeds maximum")
		}
		if (len(compressedData) - 1) > *uncompressedDataSize {
			return fmt.Errorf("compressed data size exceeds uncompressed data size")
		}

		*uncompressedDataSize = len(compressedData) - 1
		copy(uncompressedData, compressedData[1:])
		return nil
	}

	if len(compressedData) < 2 {
		return fmt.Errorf("truncated LZFSE chunk: %d bytes", len(compressedData))
	}

	if *uncompressedDataSize < 0 || *uncompressedDataSize > len(uncompressedData) {
		return fmt.Errorf("invalid uncompressed data size: %d (buffer size %d)", *uncompressedDataSize, len(uncompressedData))
	}

	n, err := lzfse.DecompressInto(uncompressedData[:*uncompressedDataSize], compressedData)
	if errors.Is(err, lzfse.ErrOutputFull) {
		return fmt.Errorf("decompressed data exceeds buffer size (%d): %w", *uncompressedDataSize, err)
	}
	if err != nil {
		return fmt.Errorf("unable to decompress LZFSE data: %w", err)
	}

	*uncompressedDataSize = n
	return nil
}
