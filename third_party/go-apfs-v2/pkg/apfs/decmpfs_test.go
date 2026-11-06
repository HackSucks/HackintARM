package apfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"math/rand"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lzfse"
)

// decmpfs fixtures are synthesized here rather than committed, because
// pkg/compression/lzfse can compress as well as decompress. That keeps these
// tests runnable on every platform, with no macOS and no afsctool needed.
//
// Synthesis carries most of the coverage, because producing a real
// LZFSE-compressed file needs macOS plus afsctool. It is not the only coverage:
// compressed.txt in testdata/cli/basic.dmg is a genuine decmpfs file — type 8,
// LZVN in a resource fork, written by ditto --hfsCompression — so the
// acceptance suite exercises that one path against bytes macOS produced. The
// vendor DMG used for acceptance testing has 675 regular files and not one
// compressed, so it contributes nothing here. These synthesized tests remain
// the fast, cross-platform layer that covers the types no fixture reaches.

// decmpfsHeader builds the 16-byte com.apple.decmpfs header: the "fpmc" magic,
// the compression type, and the uncompressed size.
func decmpfsHeader(compressionType uint32, size uint64) []byte {
	header := make([]byte, CompressedDataHeaderSize)
	copy(header[0:4], CompressedDataHeaderSignature[:])
	binary.LittleEndian.PutUint32(header[4:8], compressionType)
	binary.LittleEndian.PutUint64(header[8:16], size)
	return header
}

// inlineAttr builds a com.apple.decmpfs attribute value holding its payload
// inline: the header followed by the single compressed block.
func inlineAttr(compressionType uint32, size uint64, payload []byte) []byte {
	return append(decmpfsHeader(compressionType, size), payload...)
}

// rawEscaped stores a chunk uncompressed behind the one-byte marker macOS
// writes. lzfse.Compress never produces this form — even its incompressible
// fallback emits a "bvx-" block, magic and all — so a fixture exercising the
// escape has to build it deliberately.
func rawEscaped(chunk []byte) []byte {
	return append([]byte{0xff}, chunk...)
}

// lzfseResourceFork builds a decmpfs type-12 resource fork from raw: a flat
// table of little-endian uint32 offsets at offset 0 with one trailing
// end-of-table entry, then the chunks themselves. Chunk indices in rawEscape
// are stored uncompressed behind the escape marker.
func lzfseResourceFork(t *testing.T, raw []byte, rawEscape map[int]bool) []byte {
	t.Helper()

	var chunks [][]byte
	for start := 0; start < len(raw); start += CompressedDataHandleBlockSize {
		end := min(start+CompressedDataHandleBlockSize, len(raw))
		index := len(chunks)

		if rawEscape[index] {
			chunks = append(chunks, rawEscaped(raw[start:end]))
			continue
		}
		compressed, err := lzfse.Compress(raw[start:end])
		if err != nil {
			t.Fatalf("compressing chunk %d: %v", index, err)
		}
		chunks = append(chunks, compressed)
	}

	// The table holds one entry per chunk plus a trailing end offset, so the
	// first entry is itself the table size.
	tableBytes := 4 * (len(chunks) + 1)
	fork := make([]byte, tableBytes)
	offset := uint32(tableBytes)
	for i, chunk := range chunks {
		binary.LittleEndian.PutUint32(fork[i*4:], offset)
		offset += uint32(len(chunk))
		fork = append(fork, chunk...)
	}
	binary.LittleEndian.PutUint32(fork[len(chunks)*4:], offset)
	return fork
}

// compressiblePattern returns n bytes that compress well.
func compressiblePattern(n int) []byte {
	return bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog "), n/44+1)[:n]
}

// incompressible returns n deterministic pseudo-random bytes. The seed is
// explicit so the fixture is identical on every platform and Go version.
func incompressible(seed int64, n int) []byte {
	buf := make([]byte, n)
	r := rand.New(rand.NewSource(seed))
	r.Read(buf)
	return buf
}

// readAll reads size bytes from a decompressing stream.
func readAll(t *testing.T, stream *DataStream, size int) []byte {
	t.Helper()
	out := make([]byte, size)
	if _, err := io.ReadFull(stream, out); err != nil {
		t.Fatalf("reading %d bytes: %v", size, err)
	}
	return out
}

// openDecmpfs wraps a decmpfs payload in the stream pair the reader builds.
func openDecmpfs(t *testing.T, payload []byte, uncompressedSize uint64, method int) *DataStream {
	t.Helper()
	compressed, err := NewDataStreamFromData(payload)
	if err != nil {
		t.Fatalf("NewDataStreamFromData: %v", err)
	}
	stream, err := NewDataStreamFromCompressedDataStream(compressed, uncompressedSize, method)
	if err != nil {
		t.Fatalf("NewDataStreamFromCompressedDataStream: %v", err)
	}
	if reader, ok := stream.readerAt.(*compressedDataReader); ok {
		reader.SetFileHandle(bytes.NewReader(payload))
	}
	return stream
}

// The mapping itself is exercised in internal/decmpfs, which owns it. What is
// checked here is that this package's wrapper still reaches it and still speaks
// in this package's method constants -- the aliases would compile even if the
// two drifted apart numerically.
func TestInternalCompressionMethodLZFSE(t *testing.T) {
	supported := map[uint32]int{
		1:  CompressionMethodNone,
		9:  CompressionMethodRawMarked,
		10: CompressionMethodRawMarked,
		13: CompressionMethodLZBITMAP,
		14: CompressionMethodLZBITMAP,
		3:  CompressionMethodDeflate,
		4:  CompressionMethodDeflate,
		7:  CompressionMethodLZVN,
		8:  CompressionMethodLZVN,
		11: CompressionMethodLZFSE,
		12: CompressionMethodLZFSE,
	}
	for decmpfsType, want := range supported {
		got, err := internalCompressionMethod(decmpfsType)
		if err != nil {
			t.Errorf("type %d: %v", decmpfsType, err)
			continue
		}
		if got != want {
			t.Errorf("type %d maps to method %d, want %d", decmpfsType, got, want)
		}
	}

	for _, decmpfsType := range []uint32{5, 99} {
		if _, err := internalCompressionMethod(decmpfsType); err == nil {
			t.Errorf("type %d is not decodable but returned no error", decmpfsType)
		}
	}
}

func TestNewCompressedDataHandleAcceptsLZFSE(t *testing.T) {
	stream, err := NewDataStreamFromData([]byte("payload"))
	if err != nil {
		t.Fatalf("NewDataStreamFromData: %v", err)
	}
	handle, err := NewCompressedDataHandle(stream, 64, CompressionMethodLZFSE)
	if err != nil {
		t.Fatalf("NewCompressedDataHandle rejected LZFSE: %v", err)
	}
	if handle.SegmentData == nil {
		t.Error("SegmentData buffer was not allocated for LZFSE")
	}
}

// TestLZFSEResourceForkRoundTrip is the headline case: a multi-block type-12
// resource fork, including one chunk stored through the raw escape. The escaped
// chunk is a full 64 KiB block, so with its marker byte it is exactly 65537
// bytes — the size the segment scratch buffer is deliberately built for.
func TestLZFSEResourceForkRoundTrip(t *testing.T) {
	// Four blocks: three full and an 8 KiB tail.
	raw := make([]byte, 3*CompressedDataHandleBlockSize+8192)
	copy(raw, compressiblePattern(len(raw)))
	copy(raw[CompressedDataHandleBlockSize:], incompressible(1, CompressedDataHandleBlockSize))

	fork := lzfseResourceFork(t, raw, map[int]bool{1: true})
	stream := openDecmpfs(t, fork, uint64(len(raw)), CompressionMethodLZFSE)

	t.Run("sequential read", func(t *testing.T) {
		if got := readAll(t, stream, len(raw)); !bytes.Equal(got, raw) {
			t.Error("sequential read of the resource fork did not match the source")
		}
	})

	t.Run("read across a block boundary", func(t *testing.T) {
		const offset, length = 100_000, 70_000
		got := make([]byte, length)
		if _, err := stream.ReadAt(got, offset); err != nil {
			t.Fatalf("ReadAt: %v", err)
		}
		if !bytes.Equal(got, raw[offset:offset+length]) {
			t.Error("read spanning two blocks did not match the source")
		}
	})

	t.Run("read the tail", func(t *testing.T) {
		got := make([]byte, 10)
		if _, err := stream.ReadAt(got, int64(len(raw)-10)); err != nil {
			t.Fatalf("ReadAt: %v", err)
		}
		if !bytes.Equal(got, raw[len(raw)-10:]) {
			t.Error("tail read did not match the source")
		}
	})
}

// TestInlineAttrRoundTrip covers decmpfs data stored inline in the attribute
// rather than in a resource fork. This never worked for any method: the caller
// stripped the 16-byte header before handing the payload to the block-offset
// loader, whose inline path detects inline storage by finding the "fpmc" magic
// at offset zero and skips the header itself.
func TestInlineAttrRoundTrip(t *testing.T) {
	payload := compressiblePattern(3000)

	lzfseChunk, err := lzfse.Compress(payload)
	if err != nil {
		t.Fatalf("lzfse.Compress: %v", err)
	}
	lzvnChunk := lzfse.CompressLZVN(payload)

	var zlibBuf bytes.Buffer
	zw := zlib.NewWriter(&zlibBuf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}

	cases := []struct {
		name        string
		decmpfsType uint32
		method      int
		chunk       []byte
	}{
		{"zlib", 3, CompressionMethodDeflate, zlibBuf.Bytes()},
		{"lzvn", 7, CompressionMethodLZVN, lzvnChunk},
		{"lzfse", 11, CompressionMethodLZFSE, lzfseChunk},
		{"lzfse raw escape", 11, CompressionMethodLZFSE, rawEscaped(payload)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attr := inlineAttr(tc.decmpfsType, uint64(len(payload)), tc.chunk)

			// Go through the same helper getDataStream uses, so this covers the
			// code that had the bug rather than reimplementing it.
			stream, err := newInlineDecmpfsStream(attr, uint64(len(payload)), tc.method, bytes.NewReader(attr))
			if err != nil {
				t.Fatalf("newInlineDecmpfsStream: %v", err)
			}
			if got := readAll(t, stream, len(payload)); !bytes.Equal(got, payload) {
				t.Errorf("inline %s did not round-trip", tc.name)
			}

			// The header must stay attached. Stripping it is the original bug,
			// and it has to fail loudly rather than misparse the payload's
			// first bytes as a block-offset table.
			if _, err := newInlineDecmpfsStream(attr[CompressedDataHeaderSize:], uint64(len(payload)), tc.method, bytes.NewReader(attr)); err == nil {
				t.Error("a header-stripped attribute value was accepted; inline decmpfs needs the fpmc magic at offset zero")
			}
		})
	}
}

// TestFileEntryInlineDecmpfs drives the real getDataStream call site rather
// than the helper it delegates to. That distinction matters: the bug was that
// the call site stripped the 16-byte header before handing the value over, so a
// test that calls the helper directly with the full value would pass either
// way and prove nothing.
func TestFileEntryInlineDecmpfs(t *testing.T) {
	payload := compressiblePattern(3000)
	chunk, err := lzfse.Compress(payload)
	if err != nil {
		t.Fatalf("lzfse.Compress: %v", err)
	}
	attr := inlineAttr(11, uint64(len(payload)), chunk)

	// A non-nil ExtendedAttributes makes getExtendedAttributes return early, so
	// no B-tree is needed to reach the decmpfs branch.
	fe := &FileEntry{
		Inode:                         &Inode{BSDFlags: BSDFlagCompressed},
		ExtendedAttributes:            []*AttributeValues{},
		CompressedDataAttributeValues: &AttributeValues{Flags: ExtendedAttributeFlagEmbedded, ValueData: attr},
		FileHandle:                    bytes.NewReader(attr),
	}

	if err := fe.getDataStream(); err != nil {
		t.Fatalf("getDataStream: %v", err)
	}
	if fe.DataStream == nil {
		t.Fatal("getDataStream returned no data stream")
	}
	if got := readAll(t, fe.DataStream, len(payload)); !bytes.Equal(got, payload) {
		t.Error("inline decmpfs read through FileEntry did not match the source")
	}
}

// TestNewInlineDecmpfsStreamRejectsBadInput covers the guard rails on the
// inline path.
func TestNewInlineDecmpfsStreamRejectsBadInput(t *testing.T) {
	payload := compressiblePattern(64)
	chunk, err := lzfse.Compress(payload)
	if err != nil {
		t.Fatalf("lzfse.Compress: %v", err)
	}
	attr := inlineAttr(11, uint64(len(payload)), chunk)

	cases := map[string][]byte{
		"empty":            {},
		"header only":      attr[:CompressedDataHeaderSize],
		"truncated header": attr[:8],
		"wrong magic":      append([]byte("XXXX"), attr[4:]...),
		"payload stripped": attr[CompressedDataHeaderSize:],
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := newInlineDecmpfsStream(value, uint64(len(payload)), CompressionMethodLZFSE, bytes.NewReader(value)); err == nil {
				t.Error("newInlineDecmpfsStream accepted it, want an error")
			}
		})
	}
}
