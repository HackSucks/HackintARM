// DMG reader with decompression support for APFS extraction
// Based on go-apfs/pkg/disk/dmg implementation by blacktop
package disk

import (
	"bytes"
	"cmp"
	"compress/bzip2"
	"compress/zlib"
	"container/list"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lzfse"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
	"howett.net/plist"
)

const (
	sectorSize    = 0x200
	dmgFooterSize = 512
	dmgSignature  = "koly"
	mishSignature = "mish"
	udifVersion   = 4
)

// Chunk types
const (
	chunkTypeZeroFill      = 0x00000000
	chunkTypeUncompressed  = 0x00000001
	chunkTypeIgnored       = 0x00000002
	chunkTypeCompressADC   = 0x80000004
	chunkTypeCompressZLIB  = 0x80000005
	chunkTypeCompressBZ2   = 0x80000006
	chunkTypeCompressLZFSE = 0x80000007
	chunkTypeCompressLZMA  = 0x80000008
	chunkTypeComment       = 0x7ffffffe
	chunkTypeLastBlock     = 0xffffffff
)

// xzMagic identifies an XZ container; DMG chunk type 0x80000008 (ULMO) can
// carry either XZ or raw LZMA1 streams, distinguished by this magic
var xzMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}

// DMGFooter represents the UDIF Resource File footer
type DMGFooter struct {
	Signature             [4]byte
	Version               uint32
	HeaderSize            uint32
	Flags                 uint32
	RunningDataForkOffset uint64
	DataForkOffset        uint64
	DataForkLength        uint64
	RsrcForkOffset        uint64
	RsrcForkLength        uint64
	SegmentNumber         uint32
	SegmentCount          uint32
	SegmentID             [16]byte
	DataChecksum          [136]byte
	PlistOffset           uint64
	PlistLength           uint64
	Reserved1             [64]byte
	CodeSignatureOffset   uint64
	CodeSignatureLength   uint64
	Reserved2             [40]byte
	MasterChecksum        [136]byte
	ImageVariant          uint32
	SectorCount           uint64
	Reserved3             uint32
	Reserved4             uint32
	Reserved5             uint32
}

// DMGBlockData represents a partition in the DMG
type dmgBlockData struct {
	Signature        [4]byte
	Version          uint32
	StartSector      uint64
	SectorCount      uint64
	DataOffset       uint64
	BuffersNeeded    uint32
	BlockDescriptors uint32
	Reserved         [6]uint32
	Checksum         [136]byte
	ChunkCount       uint32
}

// DMGChunk represents a compressed chunk in a DMG partition
type DMGChunk struct {
	Type             uint32
	Comment          uint32
	DiskOffset       uint64 // Logical offset in bytes
	DiskLength       uint64 // Length in bytes
	CompressedOffset uint64 // Offset in DMG file
	CompressedLength uint64 // Compressed size in bytes
}

// DMGPartition represents a partition within a DMG
type DMGPartition struct {
	Name        string
	StartSector uint64
	SectorCount uint64
	DataOffset  uint64
	Chunks      []DMGChunk
}

// chunkCacheMaxBytes bounds the decompressed-chunk LRU cache. Without the
// cache every 4 KB read from the APFS layer re-decompresses an entire chunk
// (typically ~1 MB), which makes extraction unusably slow.
const chunkCacheMaxBytes = 128 << 20

// DMGReader implements io.ReaderAt for reading from compressed DMG files
type DMGReader struct {
	file             *os.File
	reader           io.ReaderAt
	size             int64
	limits           DMGLimits
	footer           DMGFooter
	partitions       []DMGPartition
	apfsPartitionIdx int
	apfsOffset       uint64
	apfsSize         uint64

	// LRU cache of decompressed chunks, keyed by chunk index
	cacheMu   sync.Mutex
	cache     map[int][]byte
	cacheLRU  *list.List // front = most recently used; values are chunk indices
	cacheElem map[int]*list.Element
	cacheSize int
}

// dmgPlist represents the structure of a DMG plist
type dmgPlist struct {
	ResourceFork *resourceFork `plist:"resource-fork"`
}

// resourceFork represents the resource-fork section
type resourceFork struct {
	Blkx []blkxEntry `plist:"blkx"`
}

// blkxEntry represents a block entry in the plist
type blkxEntry struct {
	Name   string `plist:"Name"`
	CFName string `plist:"CFName"`
	Data   []byte `plist:"Data"`
}

// OpenDMG opens a DMG file and prepares it for reading.
func OpenDMG(filename string) (*DMGReader, error) {
	return OpenDMGWithLimits(filename, DMGLimits{})
}

// OpenDMGWithLimits opens an image with explicit metadata and decoded chunk
// bounds. Zero fields use defaults; oversized or inconsistent data is rejected
// before allocation. Limits also apply while locating the filesystem partition.
func OpenDMGWithLimits(filename string, limits DMGLimits) (*DMGReader, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to open DMG: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	reader, err := NewDMGReader(file, info.Size(), limits)
	if err != nil {
		file.Close()
		return nil, err
	}
	reader.file = file
	return reader, nil
}

// NewDMGReader opens a DMG over a sized ReaderAt with explicit bounds. The
// caller owns the source; closing the DMGReader does not close it. Reads
// decompress chunks on demand.
func NewDMGReader(source io.ReaderAt, size int64, limits DMGLimits) (*DMGReader, error) {
	if size < dmgFooterSize {
		return nil, fmt.Errorf("invalid DMG size")
	}
	reader := &DMGReader{reader: source, size: size, limits: limits.defaults(), apfsPartitionIdx: -1,
		cache: make(map[int][]byte), cacheLRU: list.New(), cacheElem: make(map[int]*list.Element)}
	if err := reader.readFooter(); err != nil {
		return nil, fmt.Errorf("unable to read DMG footer: %w", err)
	}
	if err := reader.parsePlist(); err != nil {
		return nil, fmt.Errorf("unable to parse DMG plist: %w", err)
	}
	if err := reader.findAPFSPartition(); err != nil {
		return nil, fmt.Errorf("unable to find filesystem partition: %w", err)
	}
	return reader, nil
}

// Partitions returns a copy of the partition metadata, with byte-based chunks.
func (r *DMGReader) Partitions() []DMGPartition {
	parts := slices.Clone(r.partitions)
	for i := range parts {
		parts[i].Chunks = slices.Clone(parts[i].Chunks)
	}
	return parts
}

// Size returns the size of the APFS partition in bytes
func (r *DMGReader) Size() int64 {
	return int64(r.apfsSize)
}

// Close closes the file owned by OpenDMG. Sources supplied to NewDMGReader
// remain open.
func (r *DMGReader) Close() error {
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// readFooter reads the DMG footer from the end of the file
func (r *DMGReader) readFooter() error {
	if err := binary.Read(io.NewSectionReader(r.reader, r.size-dmgFooterSize, dmgFooterSize), binary.BigEndian, &r.footer); err != nil {
		return err
	}
	if string(r.footer.Signature[:]) != dmgSignature {
		return fmt.Errorf("invalid DMG signature")
	}
	f := r.footer
	end := uint64(r.size - dmgFooterSize)
	if f.SectorCount > math.MaxInt64/sectorSize || !dmgRange(f.DataForkOffset, f.DataForkLength, end) || !dmgRange(f.PlistOffset, f.PlistLength, end) || f.PlistLength > math.MaxInt {
		return fmt.Errorf("disk image footer exceeds source bounds")
	}
	if f.PlistLength > r.limits.MetadataBytes {
		return fmt.Errorf("disk image plist exceeds metadata limit")
	}
	if f.SectorCount > r.limits.ImageBytes/sectorSize {
		return fmt.Errorf("disk image exceeds decoded size limit")
	}
	return nil
}

func dmgRange(offset, length, end uint64) bool { return offset <= end && length <= end-offset }

// parsePlist parses the DMG plist to extract partition and chunk information
func (r *DMGReader) parsePlist() error {
	if r.footer.PlistLength == 0 {
		return fmt.Errorf("no plist data in DMG")
	}

	plistData := make([]byte, r.footer.PlistLength)
	if _, err := r.reader.ReadAt(plistData, int64(r.footer.PlistOffset)); err != nil {
		return fmt.Errorf("unable to read plist: %w", err)
	}

	// Parse plist using howett.net/plist library
	var dmgPlistData dmgPlist
	_, err := plist.Unmarshal(plistData, &dmgPlistData)
	if err != nil {
		return fmt.Errorf("unable to unmarshal plist: %w", err)
	}

	// Check if resource-fork exists and has blkx entries
	if dmgPlistData.ResourceFork == nil || len(dmgPlistData.ResourceFork.Blkx) == 0 {
		return fmt.Errorf("no blkx blocks found in plist")
	}

	// Parse each block (partition)
	for _, block := range dmgPlistData.ResourceFork.Blkx {
		partition, err := r.parsePartition(&block)
		if err != nil {
			// Other resources and unusable partitions do not prevent recovery
			// of a readable filesystem.
			continue
		}
		r.partitions = append(r.partitions, *partition)
	}

	if len(r.partitions) == 0 {
		return fmt.Errorf("no partitions found in DMG")
	}

	return nil
}

// parsePartition parses a single partition from a blkx entry
func (r *DMGReader) parsePartition(block *blkxEntry) (*DMGPartition, error) {
	partition := &DMGPartition{}

	// Set partition name
	partition.Name = block.Name
	if partition.Name == "" {
		partition.Name = block.CFName
	}

	if len(block.Data) == 0 {
		return nil, fmt.Errorf("no data in partition")
	}

	// Parse binary block data
	buf := bytes.NewReader(block.Data)

	// Read udifBlockData header
	var blockData dmgBlockData
	if err := binary.Read(buf, binary.BigEndian, &blockData); err != nil {
		return nil, fmt.Errorf("unable to read block data: %w", err)
	}

	if string(blockData.Signature[:]) != mishSignature {
		return nil, fmt.Errorf("invalid block signature: %s", string(blockData.Signature[:]))
	}

	partition.StartSector = blockData.StartSector
	partition.SectorCount = blockData.SectorCount
	partition.DataOffset = blockData.DataOffset

	if !dmgRange(blockData.StartSector, blockData.SectorCount, math.MaxInt64/sectorSize) || !dmgRange(r.footer.DataForkOffset, blockData.DataOffset, uint64(r.size)) || uint64(blockData.ChunkCount)*40 > uint64(buf.Len()) {
		return nil, fmt.Errorf("invalid partition bounds or chunk count")
	}
	if !dmgRange(blockData.StartSector, blockData.SectorCount, r.limits.ImageBytes/sectorSize) {
		return nil, fmt.Errorf("partition exceeds decoded size limit")
	}
	for i := uint32(0); i < blockData.ChunkCount; i++ {
		var chunk DMGChunk
		if err := binary.Read(buf, binary.BigEndian, &chunk); err != nil {
			return nil, err
		}
		if chunk.Type == chunkTypeComment || chunk.Type == chunkTypeLastBlock {
			continue
		}
		if !dmgRange(chunk.DiskOffset, chunk.DiskLength, blockData.SectorCount) {
			return nil, fmt.Errorf("chunk exceeds partition bounds")
		}
		// The limit bounds allocation, so it applies to chunks that must be
		// decoded into memory. Raw extents are served straight from the source
		// and zero fill is written without a buffer, whatever their size.
		if chunk.Type != chunkTypeUncompressed && chunk.Type != chunkTypeZeroFill && chunk.Type != chunkTypeIgnored &&
			(chunk.DiskLength > r.limits.ChunkBytes/sectorSize || chunk.CompressedLength > r.limits.ChunkBytes) {
			return nil, fmt.Errorf("chunk exceeds allocation limit")
		}
		chunk.DiskOffset = (chunk.DiskOffset + blockData.StartSector) * sectorSize
		chunk.DiskLength *= sectorSize
		if chunk.Type != chunkTypeZeroFill && chunk.Type != chunkTypeIgnored {
			base := blockData.DataOffset + r.footer.DataForkOffset
			if !dmgRange(chunk.CompressedOffset, chunk.CompressedLength, uint64(r.size)-base) {
				return nil, fmt.Errorf("chunk exceeds source bounds")
			}
			chunk.CompressedOffset += base
		}
		if chunk.Type == chunkTypeUncompressed && chunk.CompressedLength != chunk.DiskLength {
			return nil, fmt.Errorf("uncompressed chunk length mismatch")
		}
		partition.Chunks = append(partition.Chunks, chunk)
	}
	slices.SortStableFunc(partition.Chunks, func(a, b DMGChunk) int {
		return cmp.Compare(a.DiskOffset, b.DiskOffset)
	})

	return partition, nil
}

// findAPFSPartition locates the file system data partition in the DMG:
// GPT-partitioned images via the GPT entries, Apple Partition Map images
// via the blkx partition names (e.g. "Mac_OS_X (Apple_HFSX : 3)").
func (r *DMGReader) findAPFSPartition() error {
	// Parse GPT to find the partition
	if err := r.parseGPT(); err != nil {
		// No GPT: fall back to Apple Partition Map style blkx names, in
		// preference order APFS, then HFS+/HFSX
		for _, hint := range []string{"Apple_APFS", "Apple_HFSX", "Apple_HFS"} {
			for i, part := range r.partitions {
				if strings.Contains(part.Name, hint) {
					r.apfsPartitionIdx = i
					r.apfsOffset = part.StartSector * sectorSize
					r.apfsSize = part.SectorCount * sectorSize
					return nil
				}
			}
		}
		return err
	}

	if r.apfsPartitionIdx == -1 {
		return fmt.Errorf("no APFS or HFS+ partition found in DMG")
	}

	return nil
}

// parseGPT parses the GPT header and finds the APFS partition
func (r *DMGReader) parseGPT() error {
	// Find GPT header and table partitions
	var headerPart, tablePart *DMGPartition
	for i := range r.partitions {
		if r.partitions[i].Name == "GPT Header (Primary GPT Header : 1)" {
			headerPart = &r.partitions[i]
		}
		if r.partitions[i].Name == "GPT Partition Data (Primary GPT Table : 2)" {
			tablePart = &r.partitions[i]
		}
	}

	if headerPart == nil || tablePart == nil {
		// No GPT, try to find APFS partition by name
		for i, part := range r.partitions {
			if part.Name == "disk image" || part.Name == "(disk image)" ||
				part.Name == "GPT Partition Data" {
				r.apfsPartitionIdx = i
				r.apfsOffset = part.StartSector * sectorSize
				r.apfsSize = part.SectorCount * sectorSize
				return nil
			}
		}
		return fmt.Errorf("no GPT or named APFS partition found")
	}

	// Decompress GPT header
	var headerBuf bytes.Buffer
	for _, chunk := range headerPart.Chunks {
		data, err := r.decompressChunk(&chunk)
		if err != nil {
			return fmt.Errorf("unable to decompress GPT header chunk: %w", err)
		}
		if uint64(headerBuf.Len()+len(data)) > r.limits.MetadataBytes {
			return fmt.Errorf("GPT header exceeds metadata limit")
		}
		headerBuf.Write(data)
	}

	// Parse GPT header
	var gptHeader GPTHeader
	if err := binary.Read(bytes.NewReader(headerBuf.Bytes()), binary.LittleEndian, &gptHeader); err != nil {
		return fmt.Errorf("unable to read GPT header: %w", err)
	}

	if err := gptHeader.Verify(); err != nil {
		return fmt.Errorf("GPT header verification failed: %w", err)
	}

	// Decompress GPT table
	var tableBuf bytes.Buffer
	for _, chunk := range tablePart.Chunks {
		data, err := r.decompressChunk(&chunk)
		if err != nil {
			return fmt.Errorf("unable to decompress GPT table chunk: %w", err)
		}
		if uint64(tableBuf.Len()+len(data)) > r.limits.MetadataBytes {
			return fmt.Errorf("GPT table exceeds metadata limit")
		}
		tableBuf.Write(data)
	}

	// Parse GPT partitions
	if gptHeader.EntriesSize != 128 || gptHeader.EntriesCount == 0 || uint64(gptHeader.EntriesCount)*128 > uint64(tableBuf.Len()) {
		return fmt.Errorf("invalid GPT partition count or entry size")
	}
	partitions := make([]GPTPartition, gptHeader.EntriesCount)
	if err := binary.Read(bytes.NewReader(tableBuf.Bytes()), binary.LittleEndian, &partitions); err != nil {
		return fmt.Errorf("unable to read GPT partitions: %w", err)
	}

	// Find APFS partition
	for _, gptPart := range partitions {
		if gptPart.IsEmpty() {
			continue
		}
		guidStr := gptPart.Type.String()
		if guidStr == appleAPFSGUID || guidStr == appleHFSGUID {
			// Find corresponding DMG partition
			for i, dmgPart := range r.partitions {
				if dmgPart.StartSector == gptPart.StartingLBA {
					if gptPart.EndingLBA < gptPart.StartingLBA || gptPart.EndingLBA >= math.MaxInt64/sectorSize {
						return fmt.Errorf("invalid GPT filesystem bounds")
					}
					r.apfsPartitionIdx = i
					r.apfsOffset = gptPart.StartingLBA * sectorSize
					r.apfsSize = (gptPart.EndingLBA - gptPart.StartingLBA + 1) * sectorSize
					return nil
				}
			}
		}
	}

	return fmt.Errorf("APFS partition not found in GPT")
}

// ReadAt implements io.ReaderAt for decompressing DMG data on-the-fly
func (r *DMGReader) ReadAt(buf []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, fmt.Errorf("negative DMG offset")
	}
	if len(buf) == 0 {
		return 0, nil
	}
	if off >= r.Size() {
		return 0, io.EOF
	}
	want := len(buf)
	buf = buf[:min(int64(len(buf)), r.Size()-off)]
	off += int64(r.apfsOffset)
	chunks := r.partitions[r.apfsPartitionIdx].Chunks
	// Match reconstruction: gaps, ignored extents and zero-fill read as zero.
	clear(buf)
	i := sort.Search(len(chunks), func(i int) bool { return chunks[i].DiskOffset > uint64(off) }) - 1
	if i < 0 {
		i = 0
	}
	for ; i < len(chunks); i++ {
		chunk := &chunks[i]
		start, end := int64(chunk.DiskOffset), int64(chunk.DiskOffset+chunk.DiskLength)
		if start >= off+int64(len(buf)) {
			break
		}
		if end <= off || chunk.Type == chunkTypeZeroFill || chunk.Type == chunkTypeIgnored {
			continue
		}
		from, to := max(off, start), min(off+int64(len(buf)), end)
		out := buf[from-off : to-off]
		if chunk.Type == chunkTypeUncompressed {
			read, err := r.reader.ReadAt(out, int64(chunk.CompressedOffset)+from-start)
			if err != nil {
				return int(from-off) + read, err
			}
		} else {
			data, err := r.getChunk(i)
			if err != nil {
				return int(from - off), fmt.Errorf("unable to decompress chunk: %w", err)
			}
			copy(out, data[from-start:to-start])
		}
	}
	if len(buf) < want {
		return len(buf), io.EOF
	}
	return len(buf), nil
}

// getChunk returns the decompressed data for the chunk at the given index in
// the APFS partition, using an LRU cache bounded by chunkCacheMaxBytes.
func (r *DMGReader) getChunk(chunkIdx int) ([]byte, error) {
	chunk := &r.partitions[r.apfsPartitionIdx].Chunks[chunkIdx]

	r.cacheMu.Lock()
	if data, ok := r.cache[chunkIdx]; ok {
		r.cacheLRU.MoveToFront(r.cacheElem[chunkIdx])
		r.cacheMu.Unlock()
		return data, nil
	}
	r.cacheMu.Unlock()

	data, err := r.decompressChunk(chunk)
	if err != nil {
		return nil, err
	}

	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	if _, ok := r.cache[chunkIdx]; !ok {
		r.cache[chunkIdx] = data
		r.cacheElem[chunkIdx] = r.cacheLRU.PushFront(chunkIdx)
		r.cacheSize += len(data)

		for r.cacheSize > chunkCacheMaxBytes && r.cacheLRU.Len() > 1 {
			oldest := r.cacheLRU.Back()
			oldIdx := oldest.Value.(int)
			r.cacheSize -= len(r.cache[oldIdx])
			delete(r.cache, oldIdx)
			delete(r.cacheElem, oldIdx)
			r.cacheLRU.Remove(oldest)
		}
	}

	return data, nil
}

// decompressChunk decompresses a single DMG chunk
func (r *DMGReader) decompressChunk(chunk *DMGChunk) ([]byte, error) {
	if chunk.Type == chunkTypeComment || chunk.Type == chunkTypeLastBlock {
		return nil, nil
	}
	if chunk.DiskLength >= math.MaxInt || chunk.CompressedOffset > math.MaxInt64 || chunk.CompressedLength > math.MaxInt64-chunk.CompressedOffset {
		return nil, fmt.Errorf("chunk size or offset overflows")
	}
	// Reconstruction builds a reader directly, so bound the chunk here rather
	// than trusting a constructor to have filled the limits in.
	if limits := r.limits.defaults(); chunk.DiskLength > limits.ChunkBytes || chunk.CompressedLength > limits.ChunkBytes {
		return nil, fmt.Errorf("chunk exceeds allocation limit")
	}
	if chunk.Type == chunkTypeZeroFill || chunk.Type == chunkTypeIgnored {
		return make([]byte, chunk.DiskLength), nil
	}
	// A decoder reads its input in small pieces, so the compressed extent is
	// read once rather than once per piece: streaming it from the source costs
	// a read for every window the codec asks for. ChunkBytes bounds this, and
	// extents that need no decoding never reach here.
	input := make([]byte, chunk.CompressedLength)
	if _, err := r.reader.ReadAt(input, int64(chunk.CompressedOffset)); err != nil {
		return nil, err
	}
	compressed := bytes.NewReader(input)
	var stream io.Reader = compressed
	switch chunk.Type {
	case chunkTypeUncompressed:
	case chunkTypeCompressZLIB:
		z, err := zlib.NewReader(compressed)
		if err != nil {
			return nil, err
		}
		defer z.Close()
		stream = z
	case chunkTypeCompressBZ2:
		stream = bzip2.NewReader(compressed)
	case chunkTypeCompressLZMA:
		var err error
		if bytes.HasPrefix(input, xzMagic) {
			stream, err = xz.NewReader(compressed)
		} else {
			stream, err = lzma.NewReader(compressed)
		}
		if err != nil {
			return nil, err
		}
	case chunkTypeCompressADC, chunkTypeCompressLZFSE:
		var output []byte
		var err error
		if chunk.Type == chunkTypeCompressADC {
			output, err = DecompressADC(input, int(chunk.DiskLength))
		} else {
			if err := checkLZFSESize(input, chunk.DiskLength); err != nil {
				return nil, err
			}
			output, err = lzfse.Decompress(input)
		}
		if err != nil {
			return nil, err
		}
		if uint64(len(output)) != chunk.DiskLength {
			return nil, fmt.Errorf("decompressed chunk length mismatch")
		}
		return output, nil
	default:
		return nil, fmt.Errorf("unsupported chunk type: 0x%x", chunk.Type)
	}
	output, err := io.ReadAll(io.LimitReader(stream, int64(chunk.DiskLength)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(output)) != chunk.DiskLength {
		return nil, fmt.Errorf("decompressed chunk length mismatch")
	}
	return output, nil
}
