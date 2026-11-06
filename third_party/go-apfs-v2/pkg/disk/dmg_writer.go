// UDIF/DMG writer (encoder): the inverse of dmg_reader.go. Produces a valid
// UDIF DMG from a set of source blocks, and can losslessly repack an existing
// DMG by reconstructing its raw image layout and re-encoding it.
//
// On-disk layout produced (all multi-byte fields BIG-ENDIAN):
//
//	[data fork: concatenated compressed chunks]
//	[XML plist: resource-fork -> blkx array of mish blocks]
//	[512-byte "koly" trailer]
//
// Every mish block uses DataOffset=0, so each chunk's CompressedOffset is an
// absolute position within the data fork (which itself starts at file offset
// 0, DataForkOffset=0). This matches how Apple's hdiutil lays out its images
// and how dmg_reader.go inverts the offsets.
package disk

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"runtime"
	"sync"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lzfse"
	"github.com/ulikunitz/xz"
)

// Compression selects the chunk compressor used by the encoder.
type Compression int

const (
	// CompressionZlib compresses each non-zero chunk with zlib (UDZO chunk
	// type), falling back to raw storage when compression does not shrink the
	// chunk. It is the library default and is understood by both this package's
	// reader and hdiutil.
	CompressionZlib Compression = iota
	// CompressionNone stores every non-zero chunk raw (uncompressed).
	CompressionNone
	// CompressionLZFSE compresses each non-zero chunk with LZFSE (ULFO chunk
	// type), Apple's modern DMG codec. It gives a better ratio than zlib at
	// higher speed and is what hdiutil produces by default on recent macOS.
	// Like the others it falls back to raw storage for a chunk it cannot shrink.
	CompressionLZFSE
	// CompressionLZMA compresses each non-zero chunk with LZMA (ULMO chunk
	// type), the raw LZMA1 "alone" stream both this package's reader and hdiutil
	// accept. It gives the best ratio of the set at the cost of speed.
	CompressionLZMA
)

// EncodeOptions controls how EncodeUDIF/RepackDMG produce a DMG.
type EncodeOptions struct {
	// Compression is the chunk compressor (default CompressionZlib).
	Compression Compression
	// ChunkSectors is the number of 512-byte sectors per chunk
	// (default encodeDefaultChunkSectors). Larger chunks compress slightly
	// better; smaller chunks give finer random-access granularity.
	ChunkSectors uint64
	// NoChecksums disables CRC32 checksum emission (all checksum fields are
	// written as UDIF "none", type 0). By default CRC32 (type 2) checksums
	// are emitted for each block, the data fork, and the master checksum.
	NoChecksums bool
	// ZlibLevel is the zlib compression level (zlib.DefaultCompression when 0
	// is passed via the option struct is treated as default). Accepts the
	// standard compress/zlib levels.
	ZlibLevel int
	// Workers is how many chunks are compressed at once (runtime.GOMAXPROCS
	// when 0). The output is the same for any value: chunks are compressed
	// concurrently but written in order.
	Workers int
}

const (
	encodeDefaultChunkSectors = 2048 // 1 MiB chunks
	udifChecksumTypeNone      = 0
	udifChecksumTypeCRC32     = 2
)

// SourceBlock is one blkx block to encode. Its raw bytes cover the half-open
// sector range [StartSector, StartSector+SectorCount).
type SourceBlock struct {
	Name        string
	CFName      string
	ID          string
	Attributes  string
	StartSector uint64
	// SectorCount is the number of 512-byte sectors the block covers. When
	// Data is non-nil it must equal len(Data)/512; otherwise it is authoritative.
	SectorCount uint64
	// Data is the exact uncompressed bytes for the block, length a multiple of
	// 512. A nil Data and a nil Reader mean an all-zero block of SectorCount
	// sectors.
	Data []byte
	// Reader supplies the block's uncompressed bytes lazily, covering
	// [0, SectorCount*512) in block-relative coordinates. It is the alternative
	// to Data for a block too large to hold in memory; setting both is an error.
	//
	// The encoder reads it in ascending, chunk-sized windows and never retains
	// more than one chunk, so a block of any size costs a fixed amount of memory.
	Reader io.ReaderAt
}

// udifPlist mirrors the plist shape produced/consumed by hdiutil and this
// package's reader. It is used for both marshalling (writer) and unmarshalling
// (reconstruction) and carries every key hdiutil emits per blkx entry.
type udifPlist struct {
	ResourceFork udifResourceFork `plist:"resource-fork"`
}

type udifResourceFork struct {
	Blkx []udifBlkx `plist:"blkx"`
}

type udifBlkx struct {
	Attributes string `plist:"Attributes"`
	CFName     string `plist:"CFName"`
	Data       []byte `plist:"Data"`
	ID         string `plist:"ID"`
	Name       string `plist:"Name"`
}

func resolveEncodeOptions(o *EncodeOptions) EncodeOptions {
	out := EncodeOptions{
		Compression:  CompressionZlib,
		ChunkSectors: encodeDefaultChunkSectors,
		ZlibLevel:    zlib.DefaultCompression,
	}
	if o != nil {
		out.Compression = o.Compression
		out.NoChecksums = o.NoChecksums
		if o.ChunkSectors != 0 {
			out.ChunkSectors = o.ChunkSectors
		}
		if o.ZlibLevel != 0 {
			out.ZlibLevel = o.ZlibLevel
		}
		out.Workers = o.Workers
	}
	if out.Workers <= 0 {
		out.Workers = runtime.GOMAXPROCS(0)
	}
	if out.Compression == CompressionNone {
		out.Workers = 1 // nothing to compute
	}
	return out
}

// udifChecksum builds a 136-byte UDIFChecksum: uint32 Type, uint32 Size(bits),
// then 128 bytes of data. For CRC32 the 32-bit value is stored big-endian in
// the first 4 data bytes. A none checksum is all zeros.
func udifChecksum(crc uint32, none bool) [136]byte {
	var out [136]byte
	if none {
		return out
	}
	binary.BigEndian.PutUint32(out[0:4], udifChecksumTypeCRC32)
	binary.BigEndian.PutUint32(out[4:8], 32) // size in bits
	binary.BigEndian.PutUint32(out[8:12], crc)
	return out
}

// dataForkWriter counts bytes and CRC32s the data fork as it is streamed out.
type dataForkWriter struct {
	w   io.Writer
	crc hash.Hash32
	n   uint64
}

func (d *dataForkWriter) Write(p []byte) (int, error) {
	n, err := d.w.Write(p)
	if n > 0 {
		d.crc.Write(p[:n])
		d.n += uint64(n)
	}
	return n, err
}

// isAllZero reports whether b is entirely zero bytes.
func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// encodeChunkRecord serialises one chunk record in the exact field order the
// reader expects: Type, Comment, SectorNumber, SectorCount, CompressedOffset,
// CompressedLength (all big-endian).
func encodeChunkRecord(buf *bytes.Buffer, typ uint32, sectorNumber, sectorCount, compressedOffset, compressedLength uint64) {
	var rec [40]byte
	binary.BigEndian.PutUint32(rec[0:4], typ)
	binary.BigEndian.PutUint32(rec[4:8], 0) // Comment
	binary.BigEndian.PutUint64(rec[8:16], sectorNumber)
	binary.BigEndian.PutUint64(rec[16:24], sectorCount)
	binary.BigEndian.PutUint64(rec[24:32], compressedOffset)
	binary.BigEndian.PutUint64(rec[32:40], compressedLength)
	buf.Write(rec[:])
}

// EncodeUDIF writes a complete UDIF DMG for the given source blocks to dst.
// Blocks are emitted in slice order; each block's chunks are written to the
// data fork with absolute CompressedOffsets. dst is written strictly in order
// (data fork, plist, koly trailer) so it need not be seekable.
func EncodeUDIF(dst io.Writer, blocks []SourceBlock, opts *EncodeOptions) error {
	o := resolveEncodeOptions(opts)
	if len(blocks) == 0 {
		return fmt.Errorf("EncodeUDIF: no source blocks")
	}

	dfw := &dataForkWriter{w: dst, crc: crc32.NewIEEE()}

	var (
		blkxEntries  []udifBlkx
		blockCRCs    []uint32
		totalSectors uint64
		largest      uint64
	)

	// One chunk-sized window, shared by every block that reads lazily. This is
	// the whole of the encoder's per-image memory cost: a block is never held.
	var window []byte
	for i := range blocks {
		if blocks[i].Reader != nil {
			window = make([]byte, o.ChunkSectors*sectorSize)
			break
		}
	}

	for bi := range blocks {
		blk := &blocks[bi]
		if blk.Data != nil && blk.Reader != nil {
			return fmt.Errorf("EncodeUDIF: block %q sets both Data and Reader", blk.Name)
		}
		secCount := blk.SectorCount
		if blk.Data != nil {
			if len(blk.Data)%sectorSize != 0 {
				return fmt.Errorf("EncodeUDIF: block %q data length %d not a multiple of %d", blk.Name, len(blk.Data), sectorSize)
			}
			secCount = uint64(len(blk.Data)) / sectorSize
		}

		mish, blockCRC, blockLargest, err := encodeBlock(dfw, bi, blk, secCount, &o, window)
		if err != nil {
			return fmt.Errorf("EncodeUDIF: block %q: %w", blk.Name, err)
		}
		largest = max(largest, blockLargest)

		blkxEntries = append(blkxEntries, udifBlkx{
			Attributes: firstNonEmpty(blk.Attributes, "0x0050"),
			CFName:     firstNonEmpty(blk.CFName, blk.Name),
			Data:       mish,
			ID:         firstNonEmpty(blk.ID, fmt.Sprintf("%d", bi)),
			Name:       blk.Name,
		})
		blockCRCs = append(blockCRCs, blockCRC)

		if end := blk.StartSector + secCount; end > totalSectors {
			totalSectors = end
		}
	}

	// Like hdiutil, every block records the allowance of the image's largest chunk.
	for _, entry := range blkxEntries {
		binary.BigEndian.PutUint32(entry.Data[mishBuffersNeededOffset:], buffersNeeded(&o, largest))
	}

	dataForkLen := dfw.n
	dataForkCRC := dfw.crc.Sum32()

	// Marshal the plist. Kept separate from the reader's structs so both read
	// and write paths can share udifPlist.
	plistBytes, err := marshalPlist(blkxEntries)
	if err != nil {
		return fmt.Errorf("EncodeUDIF: marshal plist: %w", err)
	}
	if _, err := dst.Write(plistBytes); err != nil {
		return fmt.Errorf("EncodeUDIF: write plist: %w", err)
	}

	// Master checksum: CRC32 over the concatenation of each block's CRC32
	// value (big-endian). Matches the libdmg-hfsplus / hdiutil convention.
	masterHash := crc32.NewIEEE()
	var tmp [4]byte
	for _, c := range blockCRCs {
		binary.BigEndian.PutUint32(tmp[:], c)
		masterHash.Write(tmp[:])
	}
	masterCRC := masterHash.Sum32()

	footer := DMGFooter{
		Version:        udifVersion,
		HeaderSize:     dmgFooterSize,
		Flags:          1,
		DataForkOffset: 0,
		DataForkLength: dataForkLen,
		SegmentNumber:  1,
		SegmentCount:   1,
		DataChecksum:   udifChecksum(dataForkCRC, o.NoChecksums),
		PlistOffset:    dataForkLen, // DataForkOffset=0, plist follows the data fork
		PlistLength:    uint64(len(plistBytes)),
		MasterChecksum: udifChecksum(masterCRC, o.NoChecksums),
		ImageVariant:   imageVariantFor(blocks),
		SectorCount:    totalSectors,
	}
	copy(footer.Signature[:], dmgSignature)

	if err := binary.Write(dst, binary.BigEndian, &footer); err != nil {
		return fmt.Errorf("EncodeUDIF: write koly footer: %w", err)
	}

	return nil
}

// encodeBlock chunks a single source block, streams its compressed chunk data
// to dfw, and returns the serialised mish block bytes, the CRC32 of the
// block's uncompressed data and the length of its largest LZFSE or LZMA chunk.
// The caller sets BuffersNeeded once every block is encoded.
//
// Chunks are read, and the block CRC taken, in order on the calling goroutine.
// With more than one worker they are compressed concurrently and written in
// order by a single consumer, so the output does not depend on the worker
// count. window, when non-nil, is a scratch buffer of ChunkSectors*512 bytes
// shared across blocks, used only when the block reads lazily with one worker.
func encodeBlock(dfw *dataForkWriter, index int, blk *SourceBlock, secCount uint64, o *EncodeOptions, window []byte) ([]byte, uint32, uint64, error) {
	e := &blockEncoder{dfw: dfw, o: o, crc: crc32.NewIEEE()}
	var err error
	if o.Workers <= 1 {
		err = e.sequential(blk, secCount, window)
	} else {
		err = e.parallel(blk, secCount)
	}
	if err != nil {
		return nil, 0, 0, err
	}

	// Terminator chunk: type 0xffffffff, SectorNumber = end sector, no data.
	encodeChunkRecord(&e.chunks, chunkTypeLastBlock, secCount, 0, dfw.n, 0)
	e.chunkCount++

	header := dmgBlockData{
		Version:          1,
		StartSector:      blk.StartSector,
		SectorCount:      secCount,
		DataOffset:       0,
		BlockDescriptors: uint32(index),
		Checksum:         udifChecksum(e.crc.Sum32(), o.NoChecksums),
		ChunkCount:       e.chunkCount,
	}
	copy(header.Signature[:], mishSignature)

	var out bytes.Buffer
	if err := binary.Write(&out, binary.BigEndian, &header); err != nil {
		return nil, 0, 0, err
	}
	out.Write(e.chunks.Bytes())

	return out.Bytes(), e.crc.Sum32(), e.largest, nil
}

// mishBuffersNeededOffset is where BuffersNeeded sits in a serialised mish
// header, after Signature, Version, StartSector, SectorCount and DataOffset.
const mishBuffersNeededOffset = 32

// buffersNeeded is the BuffersNeeded that hdiutil records, measured from its
// own images: a chunk plus 8 sectors for UDZO, and a chunk plus the image's
// largest compressed chunk for ULFO and ULMO. The macOS disk image driver
// relies on it: given zlib's figure, macOS 26 fails to attach or read LZFSE
// and LZMA images that hdiutil verify accepts.
func buffersNeeded(o *EncodeOptions, largest uint64) uint32 {
	switch o.Compression {
	case CompressionLZFSE, CompressionLZMA:
		return uint32(o.ChunkSectors + (largest+sectorSize-1)/sectorSize)
	}
	return uint32(o.ChunkSectors) + 8
}

// blockEncoder holds one block's output: its chunk records, written to the
// data fork in order, and the CRC32 of its uncompressed bytes.
type blockEncoder struct {
	dfw        *dataForkWriter
	o          *EncodeOptions
	crc        hash.Hash32
	chunks     bytes.Buffer
	chunkCount uint32
	largest    uint64
}

// chunkJob is one chunk on its way through the pipeline. raw is nil for an
// all-zero chunk, which is recorded without data.
type chunkJob struct {
	sector, n uint64
	raw       []byte
	buf       []byte // pooled buffer backing raw, returned once written
	done      chan struct{}
	payload   []byte
	typ       uint32
	err       error
}

// chunkRaw returns the chunk of n sectors at sector: a slice of the block's
// data, or the block's bytes read into buf. nil means all zeros.
func chunkRaw(blk *SourceBlock, sector, n uint64, buf []byte) ([]byte, error) {
	switch {
	case blk.Data != nil:
		start := sector * sectorSize
		return blk.Data[start : start+n*sectorSize], nil
	case blk.Reader != nil:
		raw := buf[:n*sectorSize]
		if _, err := readFullAt(blk.Reader, raw, int64(sector*sectorSize)); err != nil {
			return nil, fmt.Errorf("read sector %d: %w", sector, err)
		}
		return raw, nil
	}
	return nil, nil // neither Data nor Reader: all zeros
}

// checksum folds a chunk into the block CRC and reports whether it is all
// zeros, which is stored as a zero-fill chunk with no data.
func (e *blockEncoder) checksum(raw []byte, n uint64) (zero bool) {
	if raw == nil || isAllZero(raw) {
		// Zeros still count towards the CRC of the uncompressed image.
		writeZeros(e.crc, int(n*sectorSize))
		return true
	}
	e.crc.Write(raw)
	return false
}

// write appends a chunk to the data fork and records it.
func (e *blockEncoder) write(sector, n uint64, zero bool, payload []byte, typ uint32) error {
	if zero {
		encodeChunkRecord(&e.chunks, chunkTypeZeroFill, sector, n, e.dfw.n, 0)
	} else {
		coff := e.dfw.n
		if _, err := e.dfw.Write(payload); err != nil {
			return err
		}
		encodeChunkRecord(&e.chunks, typ, sector, n, coff, uint64(len(payload)))
		if typ == chunkTypeCompressLZFSE || typ == chunkTypeCompressLZMA {
			e.largest = max(e.largest, uint64(len(payload)))
		}
	}
	e.chunkCount++
	return nil
}

// sequential encodes the block one chunk at a time.
func (e *blockEncoder) sequential(blk *SourceBlock, secCount uint64, window []byte) error {
	for sector := uint64(0); sector < secCount; {
		n := min(e.o.ChunkSectors, secCount-sector)
		raw, err := chunkRaw(blk, sector, n, window)
		if err != nil {
			return err
		}
		var payload []byte
		var typ uint32
		zero := e.checksum(raw, n)
		if !zero {
			if payload, typ, err = compressChunk(raw, e.o); err != nil {
				return err
			}
		}
		if err := e.write(sector, n, zero, payload, typ); err != nil {
			return err
		}
		sector += n
	}
	return nil
}

// parallel encodes the block with o.Workers compressors. Reading, the block
// CRC and writing stay in chunk order; at most two chunks per worker are in
// flight, and a lazily read block reads into that many pooled buffers.
func (e *blockEncoder) parallel(blk *SourceBlock, secCount uint64) error {
	workers := e.o.Workers
	inFlight := 2 * workers

	work := make(chan *chunkJob, inFlight)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				j.payload, j.typ, j.err = compressChunk(j.raw, e.o)
				close(j.done)
			}
		}()
	}

	var free chan []byte
	if blk.Reader != nil {
		free = make(chan []byte, inFlight)
		for range inFlight {
			free <- make([]byte, e.o.ChunkSectors*sectorSize)
		}
	}

	// The consumer writes chunks in order. After an error it keeps draining,
	// so the producer and workers never block on it, and returns the first.
	ordered := make(chan *chunkJob, inFlight)
	consumerErr := make(chan error, 1)
	var failed sync.Once
	stop := make(chan struct{})
	go func() {
		var first error
		for j := range ordered {
			<-j.done
			if first == nil {
				first = j.err
				if first == nil {
					first = e.write(j.sector, j.n, j.raw == nil, j.payload, j.typ)
				}
				if first != nil {
					failed.Do(func() { close(stop) })
				}
			}
			if j.buf != nil {
				free <- j.buf
			}
		}
		consumerErr <- first
	}()

	var produceErr error
	for sector := uint64(0); sector < secCount; {
		n := min(e.o.ChunkSectors, secCount-sector)
		j := &chunkJob{sector: sector, n: n, done: make(chan struct{})}
		if free != nil {
			select {
			case j.buf = <-free:
			case <-stop:
			}
			if j.buf == nil {
				break
			}
		}
		raw, err := chunkRaw(blk, sector, n, j.buf)
		if err != nil {
			produceErr = err
			if j.buf != nil {
				free <- j.buf
			}
			break
		}
		if e.checksum(raw, n) {
			close(j.done) // zero-fill: nothing to compress
		} else {
			j.raw = raw
			work <- j
		}
		ordered <- j
		sector += n
	}
	close(work)
	close(ordered)
	wg.Wait()
	if err := <-consumerErr; err != nil {
		return err
	}
	return produceErr
}

// readFullAt fills p from r at off. It exists because an io.ReaderAt is
// permitted both to return fewer bytes than asked for and to report io.EOF
// alongside a full read, so a single ReadAt call cannot be trusted to have
// filled the buffer.
func readFullAt(r io.ReaderAt, p []byte, off int64) (int, error) {
	n := 0
	for n < len(p) {
		read, err := r.ReadAt(p[n:], off+int64(n))
		n += read
		if err != nil {
			if err == io.EOF && n == len(p) {
				return n, nil
			}
			return n, err
		}
		if read == 0 {
			return n, io.ErrUnexpectedEOF
		}
	}
	return n, nil
}

var zeroScratch = make([]byte, 64<<10)

// writeZeros feeds n zero bytes into h without allocating.
func writeZeros(h hash.Hash, n int) {
	for n > 0 {
		c := n
		if c > len(zeroScratch) {
			c = len(zeroScratch)
		}
		h.Write(zeroScratch[:c])
		n -= c
	}
}

// compressChunk compresses raw with the configured compressor and returns the
// bytes to store plus the chunk type to record. When the compressor does not
// shrink the chunk — or when it is CompressionNone — the raw bytes are stored
// with type chunkTypeUncompressed, so a chunk is never grown by "compressing"
// it and the reader can always round-trip the result. The fallback is per
// chunk, so a mostly-compressible image still stores its few incompressible
// chunks raw.
func compressChunk(raw []byte, o *EncodeOptions) ([]byte, uint32, error) {
	var (
		compressed []byte
		typ        uint32
		err        error
	)
	switch o.Compression {
	case CompressionNone:
		return raw, chunkTypeUncompressed, nil
	case CompressionZlib:
		compressed, err = zlibCompress(raw, o.ZlibLevel)
		typ = chunkTypeCompressZLIB
	case CompressionLZFSE:
		compressed, err = lzfseCompress(raw)
		typ = chunkTypeCompressLZFSE
	case CompressionLZMA:
		compressed, err = lzmaCompress(raw)
		typ = chunkTypeCompressLZMA
	default:
		return nil, 0, fmt.Errorf("unknown compression %d", o.Compression)
	}
	if err != nil {
		return nil, 0, err
	}
	if len(compressed) < len(raw) {
		return compressed, typ, nil
	}
	return raw, chunkTypeUncompressed, nil
}

// lzfseCompress returns the LZFSE-compressed form of data, the payload of a
// ULFO (0x80000007) chunk.
func lzfseCompress(data []byte) ([]byte, error) {
	return lzfse.Compress(data)
}

// lzmaCompress returns the payload of a ULMO (0x80000008) chunk: an xz
// stream holding LZMA2, with no integrity check.
//
// That is what hdiutil writes -- its chunks begin with the xz magic and stream
// flags 00 00 -- and what it reads: an LZMA1 "alone" stream, which this
// writer used to emit and dmg_reader.go also accepts, fails hdiutil verify
// ("checksum failed with error 1000") and leaves the image unreadable on
// macOS. The DMG's own CRC32s cover the data, so the xz check would be
// redundant. The encoder takes no timestamps, so identical input yields
// identical output.
func lzmaCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := xz.WriterConfig{NoCheckSum: true}.NewWriter(&buf)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// zlibCompress returns the zlib-compressed form of data.
func zlibCompress(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// RepackDMG reconstructs the raw image layout of the source DMG at srcPath and
// re-encodes it losslessly to dstPath, preserving every block boundary and
// name so both this package's reader and hdiutil handle the output exactly as
// they handle the input. The chunk data is recompressed per opts.
func RepackDMG(srcPath, dstPath string, opts *EncodeOptions) error {
	blocks, _, closer, err := reconstructBlocks(srcPath)
	if err != nil {
		return fmt.Errorf("RepackDMG: reconstruct %s: %w", srcPath, err)
	}
	// The blocks read from the open DMG lazily, so it must stay open until the
	// encode finishes.
	defer closer.Close()
	if err := encodeToFile(dstPath, blocks, opts); err != nil {
		return fmt.Errorf("RepackDMG: %w", err)
	}
	return nil
}

// encodeToFile encodes blocks to a new file at dstPath through a buffered
// writer. A failure removes the partial file rather than leaving a truncated
// DMG behind, which would otherwise look like a valid output to anything that
// only checks the path exists.
func encodeToFile(dstPath string, blocks []SourceBlock, opts *EncodeOptions) error {
	out, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", dstPath, err)
	}

	fail := func(err error) error {
		out.Close()
		os.Remove(dstPath)
		return err
	}

	bw := bufio.NewWriterSize(out, 1<<20)
	if err := EncodeUDIF(bw, blocks, opts); err != nil {
		return fail(fmt.Errorf("encode: %w", err))
	}
	if err := bw.Flush(); err != nil {
		return fail(fmt.Errorf("flush: %w", err))
	}
	if err := out.Close(); err != nil {
		os.Remove(dstPath)
		return fmt.Errorf("close: %w", err)
	}
	return nil
}

// UDIF image variants. The distinction is not cosmetic: it tells DiskImages
// whether sector 0 is a partition map or the file system itself, and an image
// that gets it wrong is refused with "attach failed - Bad file descriptor"
// however sound its contents are.
const (
	imageVariantDevice    = 1 // a whole device, partition map included
	imageVariantPartition = 2 // a single file system, no partition map
)

// imageVariantFor decides which variant the block layout describes.
//
// A device image is a whole disk: hdiutil writes one for a partitioned image,
// where the blocks cover a protective MBR, the GPT headers and tables, the
// partitions and the free gaps between them. A partition image is a bare file
// system starting at sector 0, which is what this package produces when it
// wraps one -- there is no partition map to describe.
//
// Deriving this from the blocks rather than taking it as an option keeps a
// repack correct for free: repacking a partitioned image carries its map
// through and stays a device image, while repacking a bare one stays a
// partition image.
func imageVariantFor(blocks []SourceBlock) uint32 {
	if len(blocks) == 1 && blocks[0].StartSector == 0 {
		return imageVariantPartition
	}
	return imageVariantDevice
}

// wholeDiskBlock describes a raw file system image as the single Apple
// partition block a DMG wraps it in. partitionHint is the Apple partition type
// name embedded in the block name so the reader (and hdiutil) locate the file
// system, e.g. "Apple_HFSX", "Apple_HFS" or "Apple_APFS".
func wholeDiskBlock(partitionHint string, sectors uint64) SourceBlock {
	name := fmt.Sprintf("whole disk (%s : 0)", partitionHint)
	return SourceBlock{
		Name:        name,
		CFName:      name,
		ID:          "0",
		Attributes:  "0x0050",
		StartSector: 0,
		SectorCount: sectors,
	}
}

// WrapRawImageDMG writes a UDIF DMG at dstPath wrapping a raw file system
// image as a single Apple partition block. partitionHint is the Apple
// partition type name embedded in the block name so the reader (and hdiutil)
// locate the file system, e.g. "Apple_HFSX", "Apple_HFS" or "Apple_APFS".
//
// The whole image is held in memory. WrapRawImageDMGFrom takes the same image
// as an io.ReaderAt and does not.
func WrapRawImageDMG(dstPath string, raw []byte, partitionHint string, opts *EncodeOptions) error {
	if len(raw)%sectorSize != 0 {
		return fmt.Errorf("WrapRawImageDMG: raw image length %d is not a multiple of %d", len(raw), sectorSize)
	}
	block := wholeDiskBlock(partitionHint, uint64(len(raw)/sectorSize))
	block.Data = raw

	if err := encodeToFile(dstPath, []SourceBlock{block}, opts); err != nil {
		return fmt.Errorf("WrapRawImageDMG: %w", err)
	}
	return nil
}

// WrapRawImageDMGFrom writes a UDIF DMG at dstPath wrapping the raw file system
// image read from src, which must cover [0, size). It is WrapRawImageDMG
// without holding the image in memory: nothing larger than one chunk is
// retained, so src may be an *os.File of any size.
//
// The output is byte-identical to what WrapRawImageDMG produces for the same
// bytes; only where they come from differs.
func WrapRawImageDMGFrom(dstPath string, src io.ReaderAt, size int64, partitionHint string, opts *EncodeOptions) error {
	if size%sectorSize != 0 {
		return fmt.Errorf("WrapRawImageDMGFrom: raw image length %d is not a multiple of %d", size, sectorSize)
	}
	if src == nil {
		return fmt.Errorf("WrapRawImageDMGFrom: nil source")
	}
	block := wholeDiskBlock(partitionHint, uint64(size/sectorSize))
	block.Reader = src

	if err := encodeToFile(dstPath, []SourceBlock{block}, opts); err != nil {
		return fmt.Errorf("WrapRawImageDMGFrom: %w", err)
	}
	return nil
}
