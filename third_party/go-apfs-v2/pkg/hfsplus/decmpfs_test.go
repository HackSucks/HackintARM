package hfsplus

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lzfse"
)

// The committed fixture covers one decmpfs shape with bytes macOS produced:
// type 8, LZVN in a resource fork. These tests cover the shapes no fixture
// available to this project reaches -- inline storage, and a resource fork
// spanning more than one 64 KiB chunk -- by synthesizing them, which also keeps
// them runnable on Linux and Windows.

// decmpfsHeaderBytes builds the 16-byte com.apple.decmpfs header.
func decmpfsHeaderBytes(compressionType uint32, size uint64) []byte {
	h := make([]byte, decmpfs.HeaderSize)
	copy(h, decmpfs.HeaderSignature[:])
	binary.LittleEndian.PutUint32(h[4:8], compressionType)
	binary.LittleEndian.PutUint64(h[8:16], size)
	return h
}

func zlibCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// lzfseFork builds a decmpfs resource fork: a flat table of little-endian
// uint32 offsets with one trailing end-of-table entry, then the chunks.
func lzfseFork(t *testing.T, raw []byte) []byte {
	t.Helper()

	var chunks [][]byte
	for start := 0; start < len(raw); start += decmpfs.BlockSize {
		end := min(start+decmpfs.BlockSize, len(raw))
		compressed, err := lzfse.Compress(raw[start:end])
		if err != nil {
			t.Fatalf("lzfse.Compress: %v", err)
		}
		chunks = append(chunks, compressed)
	}

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

// compressedEntry builds a catalog entry for a compressed file: UF_COMPRESSED
// set, an empty data fork, and a resource fork at the given extents.
func compressedEntry(fileID CatalogNodeID, rsrc ForkData) *entry {
	return &entry{
		name: "compressed",
		file: &HFSPlusCatalogFile{
			FileID:       fileID,
			BSDInfo:      BSDInfo{FileMode: sIFREG | 0o644, OwnerFlags: ufCompressed},
			ResourceFork: rsrc,
		},
	}
}

func readAllFrom(t *testing.T, r fileReader) []byte {
	t.Helper()
	out := make([]byte, r.Size())
	if len(out) == 0 {
		return out
	}
	if _, err := r.ReadAt(out, 0); err != nil && err != io.EOF {
		t.Fatalf("ReadAt: %v", err)
	}
	return out
}

func TestDecmpfsInlineZlib(t *testing.T) {
	const fileID = CatalogNodeID(70)

	payload := bytes.Repeat([]byte("inline zlib decmpfs payload. "), 40)
	attrValue := append(decmpfsHeaderBytes(3, uint64(len(payload))), zlibCompress(t, payload)...)

	v := attrVolume(t, 512, []btRecord{
		{key: encodeAttrKey(fileID, decmpfsAttrName, 0), payload: attrInlineRecord(attrValue)},
	}, nil)

	reader, err := v.dataForkReader(compressedEntry(fileID, ForkData{}))
	if err != nil {
		t.Fatalf("dataForkReader: %v", err)
	}
	if reader.Size() != int64(len(payload)) {
		t.Errorf("size = %d, want %d", reader.Size(), len(payload))
	}
	if got := readAllFrom(t, reader); !bytes.Equal(got, payload) {
		t.Error("inline zlib content did not round-trip")
	}
}

// TestDecmpfsResourceForkMultiBlock covers a fork spanning more than one 64 KiB
// chunk, so the block table is exercised rather than just its first entry.
func TestDecmpfsResourceForkMultiBlock(t *testing.T) {
	const (
		fileID   = CatalogNodeID(80)
		nodeSize = 512
	)

	raw := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog "), 4000)[:2*decmpfs.BlockSize+1234]
	fork := lzfseFork(t, raw)

	// The attribute holds the header alone, so the data comes from the fork.
	attrValue := decmpfsHeaderBytes(12, uint64(len(raw)))

	// Round the fork up to whole blocks and place it after the tree. With one
	// header node and one leaf, the data starts at block 3.
	const dataStart = 3
	forkBlocks := (len(fork) + nodeSize - 1) / nodeSize
	data := make([]byte, forkBlocks*nodeSize)
	copy(data, fork)

	v := attrVolume(t, nodeSize, []btRecord{
		{key: encodeAttrKey(fileID, decmpfsAttrName, 0), payload: attrInlineRecord(attrValue)},
	}, data)

	e := compressedEntry(fileID, ForkData{
		LogicalSize: uint64(len(fork)),
		TotalBlocks: uint32(forkBlocks),
		Extents:     ExtentRecord{{StartBlock: dataStart, BlockCount: uint32(forkBlocks)}},
	})

	reader, err := v.dataForkReader(e)
	if err != nil {
		t.Fatalf("dataForkReader: %v", err)
	}
	if reader.Size() != int64(len(raw)) {
		t.Fatalf("size = %d, want %d", reader.Size(), len(raw))
	}
	if got := readAllFrom(t, reader); !bytes.Equal(got, raw) {
		t.Fatal("multi-block resource-fork content did not round-trip")
	}

	// A read crossing a chunk boundary must stitch the chunks together.
	const offset, length = decmpfs.BlockSize - 100, 4096
	got := make([]byte, length)
	if _, err := reader.ReadAt(got, offset); err != nil && err != io.EOF {
		t.Fatalf("ReadAt across a chunk boundary: %v", err)
	}
	if !bytes.Equal(got, raw[offset:offset+length]) {
		t.Error("a read spanning two chunks returned the wrong bytes")
	}

	// Reading past the end must report EOF rather than running the decoder on.
	if _, err := reader.ReadAt(make([]byte, 16), int64(len(raw))); err != io.EOF {
		t.Errorf("ReadAt past the end returned %v, want io.EOF", err)
	}
}

func TestDecmpfsRejectsInconsistentVolume(t *testing.T) {
	const fileID = CatalogNodeID(90)

	t.Run("flag set but no attribute", func(t *testing.T) {
		v := attrVolume(t, 512, nil, nil)
		if _, err := v.dataForkReader(compressedEntry(fileID, ForkData{})); err == nil {
			t.Error("a file with UF_COMPRESSED and no decmpfs attribute was accepted")
		}
	})

	t.Run("undecodable compression type", func(t *testing.T) {
		// Type 5 is external generation-store content, not a compression codec.
		attrValue := append(decmpfsHeaderBytes(5, 100), make([]byte, 8)...)
		v := attrVolume(t, 512, []btRecord{
			{key: encodeAttrKey(fileID, decmpfsAttrName, 0), payload: attrInlineRecord(attrValue)},
		}, nil)
		_, err := v.dataForkReader(compressedEntry(fileID, ForkData{}))
		if err == nil {
			t.Fatal("an external generation-store file was accepted")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("generation store")) {
			t.Errorf("error %q does not name the format", err)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		v := attrVolume(t, 512, []btRecord{
			{key: encodeAttrKey(fileID, decmpfsAttrName, 0), payload: attrInlineRecord(decmpfsHeaderBytes(3, 0))},
		}, nil)
		reader, err := v.dataForkReader(compressedEntry(fileID, ForkData{}))
		if err != nil {
			t.Fatalf("a zero-length compressed file was refused: %v", err)
		}
		if reader.Size() != 0 {
			t.Errorf("size = %d, want 0", reader.Size())
		}
	})
}
