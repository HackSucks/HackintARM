package decmpfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// blockIndex retains only the description of a validated on-disk index. Its
// offsets are uint64 while checking additions, even though native entries use
// uint32. Zlib offsets are relative to byte 260, not to the resource-fork base.
type blockIndex struct {
	start, end, sourceSize uint64
	count                  uint32
	zlib                   bool
	framedLZ4              bool
}

func readIndex(source Source, p []byte, offset uint64) error {
	n, err := source.ReadAt(p, int64(offset))
	if err != nil && err != io.EOF {
		return fmt.Errorf("read compression index at %d: %w", offset, err)
	}
	if n != len(p) {
		return fmt.Errorf("read compression index at %d: %w", offset, io.ErrUnexpectedEOF)
	}
	return nil
}

func (cdh *Handle) loadLargeIndex(start uint64, count uint32, zlib bool) error {
	expected := cdh.UncompressedDataSize / BlockSize
	if cdh.UncompressedDataSize%BlockSize != 0 {
		expected++
	}
	if count == 0 || uint64(count) != expected {
		return fmt.Errorf("compression block count does not match logical size")
	}
	width, entries := uint64(4), uint64(count)+1
	if zlib {
		width, entries = 8, uint64(count)
	}
	index := &blockIndex{start: start, end: start + entries*width, sourceSize: cdh.CompressedDataStream.Size(), count: count, zlib: zlib, framedLZ4: cdh.CompressionMethod == MethodLZ4}
	if index.end > index.sourceSize {
		return fmt.Errorf("compression index exceeds source extent")
	}
	previous := index.end
	for at := start; at < index.end; {
		chunk := cdh.CompressedSegmentData[:min(uint64(BlockSize), index.end-at)]
		if err := readIndex(cdh.CompressedDataStream, chunk, at); err != nil {
			return err
		}
		for offset := uint64(0); offset < uint64(len(chunk)); offset += width {
			entry := chunk[offset : offset+width]
			position := uint64(binary.LittleEndian.Uint32(entry))
			if zlib {
				position += 260
				length := uint64(binary.LittleEndian.Uint32(entry[4:]))
				if position < previous || length == 0 || length > BlockSize+1 || position+length > index.sourceSize {
					return fmt.Errorf("invalid compressed block range at index offset %d", at+offset)
				}
				previous = position + length
			} else {
				first := at+offset == start
				if position > index.sourceSize || position < previous || (!first && (position == previous || !index.framedLZ4 && position-previous > BlockSize+1)) || (first && position != index.end) {
					return fmt.Errorf("invalid compressed block offset at index offset %d", at+offset)
				}
				previous = position
			}
		}
		at += uint64(len(chunk))
	}
	cdh.NumberOfCompressedBlocks = count
	cdh.largeIndex = index
	return nil
}

func (index *blockIndex) block(source Source, block uint32) (int64, int64, error) {
	if block >= index.count {
		return 0, 0, fmt.Errorf("compression block index out of range")
	}
	width := uint64(4)
	if index.zlib {
		width = 8
	}
	var entry [8]byte
	if err := readIndex(source, entry[:], index.start+uint64(block)*width); err != nil {
		return 0, 0, err
	}
	start := uint64(binary.LittleEndian.Uint32(entry[:4]))
	end := uint64(binary.LittleEndian.Uint32(entry[4:]))
	if index.zlib {
		start += 260
		end += start
	}
	if start < index.end || end <= start || !index.framedLZ4 && end-start > BlockSize+1 || end > index.sourceSize {
		return 0, 0, fmt.Errorf("compressed block range changed or is invalid")
	}
	return int64(start), int64(end - start), nil
}

// Zlib descriptors carry explicit lengths. The final payload ends before the
// Resource Manager map, and gaps between blocks are not compressed bytes.
// Preserve the legacy small-index offset view while all reads use exact ranges.
func (cdh *Handle) loadZlibIndex(count uint32) error {
	if err := cdh.loadLargeIndex(264, count, true); err != nil {
		return err
	}
	if uint64(count)*8+264 > BlockSize {
		return nil
	}
	offsets := make([]uint32, count+1)
	for block := uint32(0); block < count; block++ {
		start, length, err := cdh.largeIndex.block(cdh.CompressedDataStream, block)
		if err != nil {
			cdh.largeIndex = nil
			return err
		}
		end := uint64(start) + uint64(length)
		if end > uint64(^uint32(0)) {
			return nil
		}
		offsets[block] = uint32(start)
		if block == count-1 {
			offsets[count] = uint32(end)
		}
	}
	cdh.CompressedBlockOffsets = offsets
	return nil
}
