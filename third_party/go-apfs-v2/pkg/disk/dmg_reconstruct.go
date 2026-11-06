// Reconstruction helpers for the UDIF/DMG writer: materialise the full raw
// disk image (or per-block raw data) from an existing DMG so it can be
// losslessly re-encoded or compared byte-for-byte.
package disk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"

	"howett.net/plist"
)

// marshalPlist renders the resource-fork/blkx plist as an XML property list,
// matching the shape hdiutil and this package's reader expect.
func marshalPlist(entries []udifBlkx) ([]byte, error) {
	doc := udifPlist{ResourceFork: udifResourceFork{Blkx: entries}}
	return plist.MarshalIndent(&doc, plist.XMLFormat, "\t")
}

// readFooterAndPlist opens dmgPath, reads its koly trailer, and unmarshals the
// resource-fork plist. It returns the open file (caller must close), the
// footer, and the parsed blkx entries.
func readFooterAndPlist(dmgPath string) (*os.File, DMGFooter, []udifBlkx, error) {
	f, err := os.Open(dmgPath)
	if err != nil {
		return nil, DMGFooter{}, nil, fmt.Errorf("open: %w", err)
	}

	var footer DMGFooter
	if _, err := f.Seek(-dmgFooterSize, io.SeekEnd); err != nil {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("seek footer: %w", err)
	}
	if err := binary.Read(f, binary.BigEndian, &footer); err != nil {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("read footer: %w", err)
	}
	if string(footer.Signature[:]) != dmgSignature {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("invalid DMG signature %q", footer.Signature[:])
	}
	// Only a zero length means the plist is absent. Offset zero is legitimate:
	// an image whose chunks are all zero-fill writes no data fork at all, so
	// its plist starts at the beginning of the file. That is exactly what a
	// large sparse image produces.
	if footer.PlistLength == 0 {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("no plist in DMG")
	}

	plistData := make([]byte, footer.PlistLength)
	if _, err := f.ReadAt(plistData, int64(footer.PlistOffset)); err != nil {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("read plist: %w", err)
	}

	var doc udifPlist
	if _, err := plist.Unmarshal(plistData, &doc); err != nil {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("unmarshal plist: %w", err)
	}
	if len(doc.ResourceFork.Blkx) == 0 {
		f.Close()
		return nil, DMGFooter{}, nil, fmt.Errorf("no blkx blocks in plist")
	}

	return f, footer, doc.ResourceFork.Blkx, nil
}

// blockReader is an io.ReaderAt over one blkx block's uncompressed bytes,
// decompressing chunks on demand rather than materialising the block.
//
// Offsets are block-relative. Ranges no chunk covers — along with zero-fill and
// ignored chunks — read as zeros, matching the pre-zeroed buffer this replaced:
// chunks are not guaranteed to tile the block, so a gap is not an error.
type blockReader struct {
	reader *DMGReader
	chunks []DMGChunk // block-relative DiskOffset, ascending
	size   int64

	// One decompressed chunk is cached. That is enough to make sequential
	// reading cheap, which is the access pattern the encoder has: it walks a
	// block once in ascending chunk-sized windows.
	mu     sync.Mutex
	cached int // index of the chunk held in data, -1 for none
	data   []byte
}

func (b *blockReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("blockReader: negative offset %d", off)
	}
	if off >= b.size {
		return 0, io.EOF
	}
	n := len(p)
	if remaining := b.size - off; int64(n) > remaining {
		n = int(remaining)
	}
	p = p[:n]

	// Everything not covered by a chunk is zero, so start from zeros and let
	// the chunks that do overlap write over the top.
	clear(p)

	b.mu.Lock()
	defer b.mu.Unlock()

	// First chunk that could overlap: the last one starting at or before off.
	i := sort.Search(len(b.chunks), func(i int) bool {
		return int64(b.chunks[i].DiskOffset) > off
	}) - 1
	if i < 0 {
		i = 0
	}

	for ; i < len(b.chunks); i++ {
		chunk := &b.chunks[i]
		start := int64(chunk.DiskOffset)
		if start >= off+int64(n) {
			break // past the requested range
		}
		end := start + int64(chunk.DiskLength)
		if end <= off {
			continue // before it
		}

		// Zero-fill and ignored chunks are already satisfied by the clear
		// above, so they cost nothing to skip.
		if chunk.Type == chunkTypeZeroFill || chunk.Type == chunkTypeIgnored {
			continue
		}

		// Overlay the intersection of [start, end) and [off, off+n).
		from := max(off, start)
		to := min(off+int64(n), end)

		// A raw extent is copied straight from the source, so reconstruction
		// never holds a chunk whose size it did not choose.
		if chunk.Type == chunkTypeUncompressed {
			if _, err := b.reader.reader.ReadAt(p[from-off:to-off], int64(chunk.CompressedOffset)+from-start); err != nil {
				return 0, fmt.Errorf("blockReader: chunk %d (type 0x%x): %w", i, chunk.Type, err)
			}
			continue
		}

		decompressed, err := b.chunkData(i)
		if err != nil {
			return 0, fmt.Errorf("blockReader: chunk %d (type 0x%x): %w", i, chunk.Type, err)
		}
		copy(p[from-off:to-off], decompressed[from-start:to-start])
	}

	return n, nil
}

// chunkData returns chunk i's decompressed bytes, reusing the cached chunk when
// it is the one asked for. The caller holds b.mu.
func (b *blockReader) chunkData(i int) ([]byte, error) {
	if b.cached == i {
		return b.data, nil
	}
	decompressed, err := b.reader.decompressChunk(&b.chunks[i])
	if err != nil {
		return nil, err
	}
	b.cached, b.data = i, decompressed
	return decompressed, nil
}

// reconstructBlocks describes every blkx block of the DMG at dmgPath as a
// SourceBlock backed by a lazy reader, preserving block names, IDs and sector
// ranges. No block is decompressed until something reads it, and none is ever
// held in full, so a DMG of any size costs a fixed amount of memory.
//
// The returned totalSectors is the full raw image size in 512-byte sectors. The
// returned Closer owns the open DMG and must outlive every use of the blocks'
// readers.
func reconstructBlocks(dmgPath string) ([]SourceBlock, uint64, io.Closer, error) {
	f, footer, blkx, err := readFooterAndPlist(dmgPath)
	if err != nil {
		return nil, 0, nil, err
	}

	// Reconstruction shares the chunk codecs with the filesystem reader.
	r := &DMGReader{reader: f}

	blocks := make([]SourceBlock, 0, len(blkx))
	var totalSectors uint64

	for _, entry := range blkx {
		if len(entry.Data) == 0 {
			continue
		}

		buf := bytes.NewReader(entry.Data)
		var bd dmgBlockData
		if err := binary.Read(buf, binary.BigEndian, &bd); err != nil {
			f.Close()
			return nil, 0, nil, fmt.Errorf("block %q: read mish header: %w", entry.Name, err)
		}
		if string(bd.Signature[:]) != mishSignature {
			// Not a mish block (e.g. license-agreement resource); skip.
			continue
		}

		chunks := make([]DMGChunk, 0, bd.ChunkCount)
		for i := uint32(0); i < bd.ChunkCount; i++ {
			var c DMGChunk
			if err := binary.Read(buf, binary.BigEndian, &c); err != nil {
				f.Close()
				return nil, 0, nil, fmt.Errorf("block %q: read chunk %d: %w", entry.Name, i, err)
			}

			switch c.Type {
			case chunkTypeComment, chunkTypeLastBlock:
				continue
			}

			// Reproduce the reader's offset arithmetic, except that DiskOffset
			// stays block-relative: these chunks address a single block, not
			// the whole image. decompressChunk does not read DiskOffset.
			c.DiskOffset = c.DiskOffset * sectorSize
			c.DiskLength = c.DiskLength * sectorSize
			c.CompressedOffset = c.CompressedOffset + bd.DataOffset + footer.DataForkOffset

			if end := c.DiskOffset + c.DiskLength; end > bd.SectorCount*sectorSize {
				f.Close()
				return nil, 0, nil, fmt.Errorf("block %q: chunk %d overflows block (off=%d len=%d cap=%d)",
					entry.Name, i, c.DiskOffset, c.DiskLength, bd.SectorCount*sectorSize)
			}
			chunks = append(chunks, c)
		}

		// The lookup in ReadAt binary-searches, so the chunks must be ordered.
		// They are written in order, but nothing in the format guarantees it.
		sort.Slice(chunks, func(i, j int) bool { return chunks[i].DiskOffset < chunks[j].DiskOffset })

		blocks = append(blocks, SourceBlock{
			Name:        entry.Name,
			CFName:      entry.CFName,
			ID:          entry.ID,
			Attributes:  entry.Attributes,
			StartSector: bd.StartSector,
			SectorCount: bd.SectorCount,
			Reader: &blockReader{
				reader: r,
				chunks: chunks,
				size:   int64(bd.SectorCount * sectorSize),
				cached: -1,
			},
		})

		if end := bd.StartSector + bd.SectorCount; end > totalSectors {
			totalSectors = end
		}
	}

	if len(blocks) == 0 {
		f.Close()
		return nil, 0, nil, fmt.Errorf("no mish blocks found in %s", dmgPath)
	}

	if footer.SectorCount > totalSectors {
		totalSectors = footer.SectorCount
	}

	return blocks, totalSectors, f, nil
}

// ReconstructRawImageTo writes the complete raw disk image encoded by the DMG
// at dmgPath to dst, placing every block at its absolute sector offset.
// Zero-fill and ignored chunks become zeros, everything else is decompressed.
// The result is a byte-exact reproduction of the original raw image.
//
// Nothing larger than one chunk is held in memory, so this works on an image of
// any size. It returns the raw image length in bytes.
func ReconstructRawImageTo(dst io.WriterAt, dmgPath string) (int64, error) {
	blocks, totalSectors, closer, err := reconstructBlocks(dmgPath)
	if err != nil {
		return 0, err
	}
	defer closer.Close()

	total := int64(totalSectors) * sectorSize
	buf := make([]byte, reconstructCopyWindow)

	for i := range blocks {
		b := &blocks[i]
		base := int64(b.StartSector) * sectorSize
		size := int64(b.SectorCount) * sectorSize
		if base+size > total {
			return 0, fmt.Errorf("block %q overflows raw image", b.Name)
		}
		if b.Reader == nil {
			continue // an all-zero block: dst is sparse or already zeroed
		}

		for off := int64(0); off < size; {
			n := int64(len(buf))
			if remaining := size - off; n > remaining {
				n = remaining
			}
			if _, err := b.Reader.ReadAt(buf[:n], off); err != nil && err != io.EOF {
				return 0, fmt.Errorf("block %q: read at %d: %w", b.Name, off, err)
			}
			if _, err := dst.WriteAt(buf[:n], base+off); err != nil {
				return 0, fmt.Errorf("block %q: write at %d: %w", b.Name, base+off, err)
			}
			off += n
		}
	}

	return total, nil
}

// reconstructCopyWindow is how much of a block ReconstructRawImageTo moves at a
// time. It is comfortably larger than a typical chunk, so a copy rarely spans
// more than two.
const reconstructCopyWindow = 4 << 20

// ReconstructRawImage returns the complete raw disk image encoded by the DMG at
// dmgPath: every block (zero-fill and ignored materialised as zeros, others
// decompressed) placed at its absolute sector offset. The result is a
// byte-exact reproduction of the original raw image.
//
// The entire image is held in memory, so it is only suitable for images that
// comfortably fit. Prefer ReconstructRawImageTo, which streams, or RepackDMG,
// which never assembles the image at all.
func ReconstructRawImage(dmgPath string) ([]byte, error) {
	var raw memWriterAt
	total, err := ReconstructRawImageTo(&raw, dmgPath)
	if err != nil {
		return nil, err
	}
	// Blocks need not cover the image, so grow to the full length: the tail of
	// an image whose last sectors no block describes reads as zeros.
	raw.grow(total)
	return raw.data, nil
}

// memWriterAt is a growable io.WriterAt over a byte slice, for the in-memory
// reconstruction path.
type memWriterAt struct{ data []byte }

func (m *memWriterAt) grow(size int64) {
	if int64(len(m.data)) < size {
		grown := make([]byte, size)
		copy(grown, m.data)
		m.data = grown
	}
}

func (m *memWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative write offset %d", off)
	}
	m.grow(off + int64(len(p)))
	return copy(m.data[off:], p), nil
}
