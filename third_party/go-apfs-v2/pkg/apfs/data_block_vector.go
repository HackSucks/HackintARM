// The APFS data block vector implementation
package apfs

import (
	"fmt"
	"io"
	"sync"
)

// DataBlockVectorSegment represents a segment in the data block vector
// Each segment corresponds to a file extent
type DataBlockVectorSegment struct {
	// The file index (extent index)
	FileIndex int

	// The physical offset in the file
	Offset int64

	// The size of the segment
	Size uint64

	// Flags for the segment
	Flags uint32

	// The logical offset where this segment starts
	LogicalOffset uint64
}

// DataBlockVector represents a vector of data blocks from file extents
type DataBlockVector struct {
	// The element size (block size)
	ElementSize uint64

	// The data handle for reading blocks
	DataHandle *FileSystemDataHandle

	// The segments
	Segments []*DataBlockVectorSegment

	// Total size
	TotalSize uint64

	// Cache of data blocks
	cache        map[int64]*DataBlock
	cacheMutex   sync.RWMutex
	cacheSize    int
	maxCacheSize int
}

// Segment flags
const (
	SegmentFlagIsSparse = 0x1 // the extent is a sparse (unallocated) range
)

// NewDataBlockVector creates a new data block vector
func NewDataBlockVector(
	ioHandle *IOHandle,
	dataHandle *FileSystemDataHandle,
	fileExtents []*FileExtent,
	isSparse bool,
) (*DataBlockVector, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	if dataHandle == nil {
		return nil, fmt.Errorf("invalid data handle")
	}

	vector := &DataBlockVector{
		ElementSize:  uint64(ioHandle.BlockSize),
		DataHandle:   dataHandle,
		Segments:     make([]*DataBlockVectorSegment, 0),
		cache:        make(map[int64]*DataBlock),
		maxCacheSize: 16, // Maximum number of cached blocks
	}

	// Build segments from file extents
	logicalOffset := uint64(0)

	for extentIndex, fileExtent := range fileExtents {
		if fileExtent == nil {
			return nil, fmt.Errorf("missing file extent: %d", extentIndex)
		}

		// Check logical offset consistency for non-sparse extents
		if !isSparse || fileExtent.PhysicalBlockNumber != 0 {
			if fileExtent.LogicalOffset != logicalOffset {
				return nil, fmt.Errorf("invalid file extent: %d - logical offset value out of bounds", extentIndex)
			}
		}

		// Determine segment flags
		segmentFlags := uint32(0)
		if isSparse && fileExtent.PhysicalBlockNumber == 0 {
			segmentFlags = SegmentFlagIsSparse
		}

		// Create segment
		segment := &DataBlockVectorSegment{
			FileIndex:     extentIndex,
			Offset:        int64(fileExtent.PhysicalBlockNumber) * int64(ioHandle.BlockSize),
			Size:          fileExtent.DataSize,
			Flags:         segmentFlags,
			LogicalOffset: logicalOffset,
		}

		vector.Segments = append(vector.Segments, segment)
		logicalOffset += fileExtent.DataSize
	}

	vector.TotalSize = logicalOffset

	return vector, nil
}

// Size returns the total size of the data in the vector
func (v *DataBlockVector) Size() (uint64, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid data block vector")
	}

	return v.TotalSize, nil
}

// ElementValueAtOffset retrieves the data block at a given logical offset
// Returns the data block and the offset within that block
func (v *DataBlockVector) ElementValueAtOffset(
	reader io.ReaderAt,
	logicalOffset int64,
) (*DataBlock, int64, error) {
	if v == nil {
		return nil, 0, fmt.Errorf("invalid data block vector")
	}

	if logicalOffset < 0 {
		return nil, 0, fmt.Errorf("invalid logical offset: %d", logicalOffset)
	}

	if uint64(logicalOffset) >= v.TotalSize {
		return nil, 0, fmt.Errorf("logical offset %d out of bounds (size: %d)", logicalOffset, v.TotalSize)
	}

	// Find the segment containing this offset
	var segment *DataBlockVectorSegment
	var segmentStartOffset uint64

	for _, seg := range v.Segments {
		segmentEndOffset := seg.LogicalOffset + seg.Size

		if uint64(logicalOffset) >= seg.LogicalOffset && uint64(logicalOffset) < segmentEndOffset {
			segment = seg
			segmentStartOffset = seg.LogicalOffset
			break
		}
	}

	if segment == nil {
		return nil, 0, fmt.Errorf("no segment found for offset %d", logicalOffset)
	}

	// Calculate offset within segment
	offsetInSegment := uint64(logicalOffset) - segmentStartOffset

	// Calculate which block within the segment
	blockIndexInSegment := offsetInSegment / v.ElementSize
	blockOffsetInSegment := offsetInSegment % v.ElementSize

	// Calculate physical offset of the block
	physicalBlockOffset := segment.Offset + int64(blockIndexInSegment*v.ElementSize)

	// Check cache
	dataBlock, err := v.getCachedBlock(physicalBlockOffset)
	if err == nil && dataBlock != nil {
		return dataBlock, int64(blockOffsetInSegment), nil
	}

	// Not in cache, need to read it
	dataBlock, err = v.DataHandle.ReadDataBlock(
		reader,
		segment.FileIndex,
		physicalBlockOffset,
		int64(v.ElementSize),
		segment.Flags,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to read data block at offset %d: %w", physicalBlockOffset, err)
	}

	// Cache the block
	v.cacheBlock(physicalBlockOffset, dataBlock)

	return dataBlock, int64(blockOffsetInSegment), nil
}

// getCachedBlock retrieves a cached data block
func (v *DataBlockVector) getCachedBlock(offset int64) (*DataBlock, error) {
	v.cacheMutex.RLock()
	defer v.cacheMutex.RUnlock()

	dataBlock, ok := v.cache[offset]
	if !ok {
		return nil, fmt.Errorf("not in cache")
	}

	return dataBlock, nil
}

// cacheBlock stores a data block in the cache
func (v *DataBlockVector) cacheBlock(offset int64, dataBlock *DataBlock) {
	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()

	// Simple cache eviction: if cache is full, clear it
	// A more sophisticated LRU cache could be implemented here
	if v.cacheSize >= v.maxCacheSize {
		v.cache = make(map[int64]*DataBlock)
		v.cacheSize = 0
	}

	v.cache[offset] = dataBlock
	v.cacheSize++
}

// Close releases resources associated with the vector
func (v *DataBlockVector) Close() error {
	if v == nil {
		return fmt.Errorf("invalid data block vector")
	}

	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()

	// Clear cache
	v.cache = nil
	v.cacheSize = 0

	// Clear segments
	v.Segments = nil

	return nil
}
