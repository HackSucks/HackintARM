package decmpfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// Handle decodes one compressed stream: it locates the chunk boundaries in the
// Source, then decompresses on demand, caching the current chunk.
//
// A Handle is stateful and not safe for concurrent use. It also holds two
// BlockSize buffers, so opening many compressed files at once is not free —
// build one per open file and let it go when the file closes.
type Handle struct {
	// The current segment offset
	CurrentSegmentOffset int64

	// CompressedDataStream is the compressed byte range. The field keeps its
	// original name because it is reachable as a field of pkg/apfs's
	// CompressedDataHandle, which is an alias for this type.
	CompressedDataStream Source

	// The uncompressed data size
	UncompressedDataSize uint64

	// The compression method
	CompressionMethod int

	// The current compressed block index
	CurrentCompressedBlockIndex uint32

	// The compressed segment data buffer
	CompressedSegmentData []byte

	// The (uncompressed) segment data buffer
	SegmentData []byte

	// The (uncompressed) segment data size
	SegmentDataSize int

	// The number of compressed blocks
	NumberOfCompressedBlocks uint32

	// The compressed block offsets for indexes that fit within one block.
	// Larger indexes stay on disk and this slice remains nil.
	CompressedBlockOffsets []uint32

	// Large on-disk indexes are validated in bounded chunks, then queried by
	// range. Retaining their complete offset array would scale with file size.
	largeIndex *blockIndex
}

// NewHandle creates a decoder for a compressed stream. compressionMethod is one
// of this package's method codes, as returned by MethodFor.
func NewHandle(
	compressedDataStream Source,
	uncompressedDataSize uint64,
	compressionMethod int,
) (*Handle, error) {
	if compressedDataStream == nil {
		return nil, fmt.Errorf("invalid compressed data stream")
	}

	switch compressionMethod {
	case MethodNone, MethodRawMarked, MethodLZBITMAP, MethodDeflate, MethodLZVN, MethodLZFSE, MethodLZ4:
	default:
		return nil, fmt.Errorf("unsupported compression method: %d", compressionMethod)
	}
	if compressionMethod == MethodNone {
		if err := validateRawSource(compressedDataStream, uncompressedDataSize); err != nil {
			return nil, err
		}
	}

	handle := &Handle{
		CurrentSegmentOffset:        0,
		CompressedDataStream:        compressedDataStream,
		UncompressedDataSize:        uncompressedDataSize,
		CompressionMethod:           compressionMethod,
		CurrentCompressedBlockIndex: 0xFFFFFFFF, // -1 in uint32
		NumberOfCompressedBlocks:    0,
	}

	// Allocate compressed segment data buffer
	// Size is BlockSize + 1 to handle edge cases
	handle.CompressedSegmentData = make([]byte, BlockSize+1)

	// Allocate uncompressed segment data buffer
	handle.SegmentData = make([]byte, BlockSize)

	return handle, nil
}

// Close releases the decoder's buffers.
func (cdh *Handle) Close() error {
	if cdh == nil {
		return fmt.Errorf("invalid compressed data handle")
	}

	// Clear buffers to free memory
	cdh.SegmentData = nil
	cdh.CompressedSegmentData = nil
	cdh.CompressedBlockOffsets = nil
	cdh.largeIndex = nil

	return nil
}

// loadCompressedBlockOffsets determines the compressed block offsets
func (cdh *Handle) loadCompressedBlockOffsets() error {
	if cdh == nil {
		return fmt.Errorf("invalid compressed data handle")
	}

	if cdh.CompressedBlockOffsets != nil || cdh.largeIndex != nil {
		return fmt.Errorf("compressed block offsets already set")
	}

	compressedDataSize := cdh.CompressedDataStream.Size()

	// Read the first 4 bytes to check for signature
	readCount, err := cdh.CompressedDataStream.ReadAt(cdh.CompressedSegmentData[:4], 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read buffer at offset 0: %w", err)
	}
	if readCount != 4 {
		return fmt.Errorf("unable to read 4 bytes at offset 0")
	}

	// Inline storage is identified by the header magic at offset zero; see
	// CheckInline for why the header must still be attached.
	isFPMC := bytes.Equal(cdh.CompressedSegmentData[:4], HeaderSignature[:])

	var compressedBlockDescriptorSize int
	var segmentDataOffset int

	if isFPMC {
		if compressedDataSize > uint64(BlockSize+1) {
			return fmt.Errorf("invalid segment data size value out of bounds")
		}
		cdh.NumberOfCompressedBlocks = 1
	} else if cdh.CompressionMethod == MethodLZ4 {
		// Framed LZ4 can exceed the logical block size, even for native raw
		// blocks. Keep the index and encoded payload on disk; stream decoding.
		start := binary.LittleEndian.Uint32(cdh.CompressedSegmentData[:4])
		if start <= 4 || start%4 != 0 {
			return fmt.Errorf("invalid LZ4 block table extent")
		}
		return cdh.loadLargeIndex(0, start/4-1, false)
	} else if cdh.CompressionMethod == MethodDeflate {
		// Read compressed descriptors offset (big endian)
		compressedDescriptorsOffset := binary.BigEndian.Uint32(cdh.CompressedSegmentData[:4])

		if compressedDescriptorsOffset != 0x00000100 {
			return fmt.Errorf("invalid compressed descriptors offset: 0x%08x", compressedDescriptorsOffset)
		}

		readSize := int(compressedDescriptorsOffset) + 16 - 4

		readCount, err = cdh.CompressedDataStream.ReadAt(cdh.CompressedSegmentData[4:4+readSize], 4)
		if err != nil && err != io.EOF {
			return fmt.Errorf("unable to read compressed header data at offset 4: %w", err)
		}
		if readCount != readSize {
			return fmt.Errorf("unable to read %d bytes at offset 4", readSize)
		}

		// Read number of compressed blocks at offset 260 (little endian)
		cdh.NumberOfCompressedBlocks = binary.LittleEndian.Uint32(cdh.CompressedSegmentData[260:264])

		if cdh.NumberOfCompressedBlocks > (0xFFFFFFFF / 8) {
			return fmt.Errorf("invalid number of compressed blocks value out of bounds")
		}
		return cdh.loadZlibIndex(cdh.NumberOfCompressedBlocks)
	} else if cdh.CompressionMethod == MethodLZVN || cdh.CompressionMethod == MethodRawMarked || cdh.CompressionMethod == MethodLZBITMAP ||
		cdh.CompressionMethod == MethodLZFSE {
		// LZVN and LZFSE resource forks share one block-table layout, and it
		// differs from zlib's: a flat array of little-endian uint32 at offset 0
		// with no HFS resource-fork header, entry i being block i's absolute
		// offset from the fork base, and one trailing entry marking the end. So
		// the first entry is itself the size of the table, and dividing it by
		// four gives the entry count.
		segmentDataOffset = 0
		compressedBlockDescriptorSize = 4

		// Read first compressed block offset (little endian)
		compressedBlockOffset := binary.LittleEndian.Uint32(cdh.CompressedSegmentData[:4])
		if compressedBlockOffset > BlockSize {
			if compressedBlockOffset%4 != 0 {
				return fmt.Errorf("invalid compressed block table alignment")
			}
			return cdh.loadLargeIndex(0, compressedBlockOffset/4-1, false)
		}

		if compressedBlockOffset <= 0x00000004 ||
			compressedBlockOffset >= uint32(BlockSize+1) {
			return fmt.Errorf("invalid compressed block offset: 0x%08x", compressedBlockOffset)
		}

		// This counts the trailing end-of-table entry as a block, so the array
		// allocated below has one unused slot. It is harmless: ReadSegmentData
		// stops at UncompressedDataSize, so the phantom block is unreachable.
		cdh.NumberOfCompressedBlocks = compressedBlockOffset / 4
	}

	// Allocate compressed block offsets array
	// Size is NumberOfCompressedBlocks + 1 to store the end offset
	if int(cdh.NumberOfCompressedBlocks) > (int(^uint(0)>>1)/4 - 1) {
		return fmt.Errorf("invalid number of compressed blocks exceeds maximum allocation size")
	}

	cdh.CompressedBlockOffsets = make([]uint32, cdh.NumberOfCompressedBlocks+1)

	var compressedBlockIndex uint32
	var previousCompressedBlockOffset uint32

	if isFPMC {
		cdh.CompressedBlockOffsets[0] = HeaderSize
		compressedBlockIndex = 1
		previousCompressedBlockOffset = HeaderSize
	} else {
		// Read the first block offset
		compressedBlockOffset := binary.LittleEndian.Uint32(cdh.CompressedSegmentData[segmentDataOffset:])
		segmentDataOffset += 4

		if compressedBlockOffset <= uint32(compressedBlockDescriptorSize) ||
			compressedBlockOffset >= uint32(BlockSize+1) {
			return fmt.Errorf("invalid compressed block offset: 0x%08x", compressedBlockOffset)
		}
		cdh.CompressedBlockOffsets[0] = compressedBlockOffset
		previousCompressedBlockOffset = compressedBlockOffset

		// Small flat tables retain the public offset view. Larger flat
		// tables and all zlib descriptors use the bounded range index.
		readSize := int(cdh.NumberOfCompressedBlocks-1) * compressedBlockDescriptorSize
		descriptors := make([]byte, readSize)

		if readSize > 0 {
			readCount, err = cdh.CompressedDataStream.ReadAt(descriptors, int64(segmentDataOffset))
			if err != nil && err != io.EOF {
				return fmt.Errorf("unable to read compressed block descriptors at offset %d: %w", segmentDataOffset, err)
			}
			if readCount != readSize {
				return fmt.Errorf("unable to read %d bytes at offset %d", readSize, segmentDataOffset)
			}
		}

		// Parse remaining block offsets, walking the descriptor buffer.
		descriptorOffset := 0
		for compressedBlockIndex = 1; compressedBlockIndex < cdh.NumberOfCompressedBlocks; compressedBlockIndex++ {
			compressedBlockOffset := binary.LittleEndian.Uint32(descriptors[descriptorOffset:])
			descriptorOffset += compressedBlockDescriptorSize

			if previousCompressedBlockOffset > compressedBlockOffset ||
				(compressedBlockOffset-previousCompressedBlockOffset) > uint32(BlockSize+1) {
				return fmt.Errorf("invalid compressed block offset: 0x%08x", compressedBlockOffset)
			}

			cdh.CompressedBlockOffsets[compressedBlockIndex] = compressedBlockOffset
			previousCompressedBlockOffset = compressedBlockOffset
		}

		compressedBlockIndex = cdh.NumberOfCompressedBlocks
	}

	// Store the end offset (size of compressed data)
	if previousCompressedBlockOffset > uint32(compressedDataSize) ||
		(uint32(compressedDataSize)-previousCompressedBlockOffset) > uint32(BlockSize+1) {
		return fmt.Errorf("invalid compressed block offset: 0x%08x", previousCompressedBlockOffset)
	}

	cdh.CompressedBlockOffsets[compressedBlockIndex] = uint32(compressedDataSize)

	return nil
}

// ReadSegmentData reads decompressed data from the current offset into
// segmentData. It is the read callback a data stream drives.
func (cdh *Handle) ReadSegmentData(
	segmentIndex int,
	segmentData []byte,
) (int, error) {
	if cdh == nil {
		return 0, fmt.Errorf("invalid compressed data handle")
	}

	if segmentIndex != 0 {
		return 0, fmt.Errorf("invalid segment index value out of bounds")
	}

	if segmentData == nil {
		return 0, fmt.Errorf("invalid segment data")
	}

	if int64(len(segmentData)) > common.Int32Max {
		return 0, fmt.Errorf("invalid segment data size value exceeds maximum")
	}

	// Get compressed block offsets if not already loaded
	if cdh.CompressedBlockOffsets == nil && cdh.largeIndex == nil {
		if err := cdh.loadCompressedBlockOffsets(); err != nil {
			return 0, fmt.Errorf("unable to determine compressed block offsets: %w", err)
		}
	}

	// Check if we've reached the end
	if uint64(cdh.CurrentSegmentOffset) >= cdh.UncompressedDataSize {
		return 0, io.EOF
	}
	// The last codec block may contain padding beyond the logical file. Never
	// expose it or request a nonexistent following descriptor at the logical end.
	if remaining := cdh.UncompressedDataSize - uint64(cdh.CurrentSegmentOffset); uint64(len(segmentData)) > remaining {
		segmentData = segmentData[:remaining]
	}

	// Calculate which compressed block we need
	compressedBlockIndex := uint32(cdh.CurrentSegmentOffset / BlockSize)
	segmentDataOffset := 0
	dataOffset := int(cdh.CurrentSegmentOffset % BlockSize)

	totalBytesRead := 0
	defer func() { cdh.CurrentSegmentOffset += int64(totalBytesRead) }()

	for len(segmentData) > segmentDataOffset {
		if compressedBlockIndex >= cdh.NumberOfCompressedBlocks {
			return totalBytesRead, fmt.Errorf("invalid compressed block index value out of bounds")
		}

		// Decompress the block if it's not the current one
		if cdh.CurrentCompressedBlockIndex != compressedBlockIndex {
			var dataStreamOffset int64
			var readSize int64
			if cdh.largeIndex != nil {
				var err error
				dataStreamOffset, readSize, err = cdh.largeIndex.block(cdh.CompressedDataStream, compressedBlockIndex)
				if err != nil {
					return totalBytesRead, err
				}
			} else {
				dataStreamOffset = int64(cdh.CompressedBlockOffsets[compressedBlockIndex])
				readSize = int64(cdh.CompressedBlockOffsets[compressedBlockIndex+1]) - int64(cdh.CompressedBlockOffsets[compressedBlockIndex])
			}

			if cdh.CompressionMethod == MethodLZ4 {
				var err error
				cdh.SegmentDataSize, err = decompressLZ4Range(io.NewSectionReader(cdh.CompressedDataStream, dataStreamOffset, readSize), readSize, cdh.SegmentData[:min(uint64(BlockSize), cdh.UncompressedDataSize-uint64(compressedBlockIndex)*BlockSize)])
				if err != nil {
					return totalBytesRead, fmt.Errorf("unable to decompress LZ4: %w", err)
				}
			} else {
				readCount, err := cdh.CompressedDataStream.ReadAt(
					cdh.CompressedSegmentData[:readSize],
					dataStreamOffset,
				)
				if err != nil && err != io.EOF {
					return totalBytesRead, fmt.Errorf("unable to read buffer at offset %d: %w", dataStreamOffset, err)
				}
				if int64(readCount) != readSize {
					return totalBytesRead, fmt.Errorf("unable to read %d bytes at offset %d", readSize, dataStreamOffset)
				}

				// Decompress the data
				cdh.SegmentDataSize = BlockSize

				// Decompress the compressed segment data
				if err := Decompress(
					cdh.CompressedSegmentData[:readCount],
					cdh.CompressionMethod,
					cdh.SegmentData,
					&cdh.SegmentDataSize,
				); err != nil {
					return totalBytesRead, fmt.Errorf("unable to decompress data: %w", err)
				}

			}

			// Verify segment data size for non-final blocks
			uncompressedBlockOffset := int64(compressedBlockIndex+1) * BlockSize
			if uint64(uncompressedBlockOffset) < cdh.UncompressedDataSize &&
				cdh.SegmentDataSize != BlockSize {
				return totalBytesRead, fmt.Errorf("invalid uncompressed segment data size value out of bounds")
			}

			cdh.CurrentCompressedBlockIndex = compressedBlockIndex
		}

		// Validate data offset
		if dataOffset >= cdh.SegmentDataSize {
			return totalBytesRead, fmt.Errorf("invalid data offset value out of bounds")
		}

		// Calculate how much data to copy from this block
		readSize := cdh.SegmentDataSize - dataOffset
		if readSize > len(segmentData)-segmentDataOffset {
			readSize = len(segmentData) - segmentDataOffset
		}

		// Copy data from the decompressed buffer
		copy(segmentData[segmentDataOffset:segmentDataOffset+readSize], cdh.SegmentData[dataOffset:dataOffset+readSize])

		dataOffset = 0
		segmentDataOffset += readSize
		totalBytesRead += readSize
		compressedBlockIndex++
	}

	return totalBytesRead, nil
}

// SeekSegmentOffset moves the decoder to an offset in the uncompressed data.
func (cdh *Handle) SeekSegmentOffset(
	segmentIndex int,
	segmentOffset int64,
) (int64, error) {
	if cdh == nil {
		return 0, fmt.Errorf("invalid compressed data handle")
	}

	if segmentIndex != 0 {
		return 0, fmt.Errorf("invalid segment index value out of bounds")
	}

	if segmentOffset < 0 {
		return 0, fmt.Errorf("invalid segment offset value out of bounds")
	}

	cdh.CurrentSegmentOffset = segmentOffset

	return segmentOffset, nil
}
