package disk

import (
	"bytes"
	"crypto/sha256"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
)

// The streaming encoder exists to keep a multi-gigabyte image out of memory. It
// must not change a single output byte while doing so: the write path is
// reproducible, and a chunking or zero-handling difference between the two
// paths would silently break that guarantee for anyone who switched.
//
// These tests are the contract. They compare the two paths directly rather than
// against a stored hash, so they keep working as the encoder legitimately
// evolves — whatever it emits, it must emit the same either way.

// streamTestImage builds a raw image that exercises every branch of the chunk
// encoder: all-zero runs that must collapse to zero-fill records, incompressible
// data that must be stored raw, highly compressible data that must be deflated,
// and a tail that is not a whole number of chunks.
func streamTestImage(chunkBytes int) []byte {
	var img []byte

	// A compressible chunk.
	img = append(img, bytes.Repeat([]byte("the quick brown fox "), chunkBytes/20+1)[:chunkBytes]...)
	// An all-zero chunk.
	img = append(img, make([]byte, chunkBytes)...)
	// An incompressible chunk, deterministic so the test is stable.
	incompressible := make([]byte, chunkBytes)
	rand.New(rand.NewSource(0x5EED)).Read(incompressible)
	img = append(img, incompressible...)
	// A half-chunk tail, so the final window is short.
	img = append(img, bytes.Repeat([]byte("tail"), chunkBytes/8)...)

	// Round to a whole number of sectors.
	if rem := len(img) % sectorSize; rem != 0 {
		img = append(img, make([]byte, sectorSize-rem)...)
	}
	return img
}

func sha256Of(b []byte) [32]byte { return sha256.Sum256(b) }

// TestEncodeUDIFReaderMatchesData is the core guarantee: the same image encoded
// through Data and through Reader must produce identical DMG bytes.
func TestEncodeUDIFReaderMatchesData(t *testing.T) {
	cases := []struct {
		name string
		opts *EncodeOptions
	}{
		{"defaults", nil},
		{"no compression", &EncodeOptions{Compression: CompressionNone}},
		{"no checksums", &EncodeOptions{NoChecksums: true}},
		{"one sector per chunk", &EncodeOptions{ChunkSectors: 1}},
		{"large chunks", &EncodeOptions{ChunkSectors: 4096}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chunkBytes := int(resolveEncodeOptions(tc.opts).ChunkSectors) * sectorSize
			img := streamTestImage(chunkBytes)
			sectors := uint64(len(img) / sectorSize)

			var viaData, viaReader bytes.Buffer
			if err := EncodeUDIF(&viaData, []SourceBlock{{
				Name: "whole disk", SectorCount: sectors, Data: img,
			}}, tc.opts); err != nil {
				t.Fatalf("encoding through Data: %v", err)
			}
			if err := EncodeUDIF(&viaReader, []SourceBlock{{
				Name: "whole disk", SectorCount: sectors, Reader: bytes.NewReader(img),
			}}, tc.opts); err != nil {
				t.Fatalf("encoding through Reader: %v", err)
			}

			if sha256Of(viaData.Bytes()) != sha256Of(viaReader.Bytes()) {
				t.Errorf("the two paths produced different DMGs (%d vs %d bytes)",
					viaData.Len(), viaReader.Len())
			}
		})
	}
}

// TestEncodeUDIFZeroBlockConventions checks the three ways a run of zeros can
// arrive all encode the same. A sparse image relies on zero runs collapsing to
// zero-fill records; if the lazy path missed that, a 15 GB sparse image would
// grow from a couple of hundred megabytes to 15 GB.
func TestEncodeUDIFZeroBlockConventions(t *testing.T) {
	const sectors = 64
	zeros := make([]byte, sectors*sectorSize)

	encode := func(block SourceBlock) []byte {
		t.Helper()
		var buf bytes.Buffer
		block.Name = "whole disk"
		block.SectorCount = sectors
		if err := EncodeUDIF(&buf, []SourceBlock{block}, nil); err != nil {
			t.Fatalf("EncodeUDIF: %v", err)
		}
		return buf.Bytes()
	}

	implicit := encode(SourceBlock{})                                     // neither Data nor Reader
	explicitData := encode(SourceBlock{Data: zeros})                      // zeros through Data
	explicitReader := encode(SourceBlock{Reader: bytes.NewReader(zeros)}) // zeros through Reader

	if sha256Of(implicit) != sha256Of(explicitData) {
		t.Error("an implicitly all-zero block differs from the same zeros passed as Data")
	}
	if sha256Of(explicitData) != sha256Of(explicitReader) {
		t.Error("zeros through Data differ from zeros through Reader")
	}
}

// TestWrapRawImageDMGFromMatchesWrapRawImageDMG checks the two public entry
// points agree, with the streaming one reading from a real file.
func TestWrapRawImageDMGFromMatchesWrapRawImageDMG(t *testing.T) {
	img := streamTestImage(encodeDefaultChunkSectors * sectorSize)
	dir := t.TempDir()

	rawPath := filepath.Join(dir, "raw.img")
	if err := os.WriteFile(rawPath, img, 0644); err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	inMemory := filepath.Join(dir, "in-memory.dmg")
	streamed := filepath.Join(dir, "streamed.dmg")

	if err := WrapRawImageDMG(inMemory, img, "Apple_APFS", nil); err != nil {
		t.Fatalf("WrapRawImageDMG: %v", err)
	}
	if err := WrapRawImageDMGFrom(streamed, src, int64(len(img)), "Apple_APFS", nil); err != nil {
		t.Fatalf("WrapRawImageDMGFrom: %v", err)
	}

	a, err := os.ReadFile(inMemory)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(streamed)
	if err != nil {
		t.Fatal(err)
	}
	if sha256Of(a) != sha256Of(b) {
		t.Errorf("WrapRawImageDMGFrom produced a different DMG (%d vs %d bytes)", len(a), len(b))
	}

	// And the result must still round-trip through the reader.
	back, err := ReconstructRawImage(streamed)
	if err != nil {
		t.Fatalf("reconstructing the streamed DMG: %v", err)
	}
	if !bytes.Equal(back, img) {
		t.Error("the streamed DMG does not reconstruct to the source image")
	}
}

// TestEncodeUDIFRejectsBothSources checks the ambiguous case is an error rather
// than a silent preference for one.
func TestEncodeUDIFRejectsBothSources(t *testing.T) {
	img := make([]byte, sectorSize)
	err := EncodeUDIF(io.Discard, []SourceBlock{{
		Name: "whole disk", SectorCount: 1, Data: img, Reader: bytes.NewReader(img),
	}}, nil)
	if err == nil {
		t.Fatal("a block setting both Data and Reader was accepted")
	}
}

// TestEncodeUDIFShortReaderIsAnError checks a Reader that cannot supply the
// sectors it promised fails rather than silently encoding whatever it had.
func TestEncodeUDIFShortReaderIsAnError(t *testing.T) {
	short := bytes.NewReader(make([]byte, sectorSize)) // one sector
	err := EncodeUDIF(io.Discard, []SourceBlock{{
		Name: "whole disk", SectorCount: 8, Reader: short, // eight promised
	}}, nil)
	if err == nil {
		t.Fatal("a Reader shorter than SectorCount was accepted")
	}
}

// zeroReaderAt is a virtual all-zero image of any size, costing no memory. It
// makes it possible to encode an image far larger than RAM.
type zeroReaderAt struct{ size int64 }

func (z zeroReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= z.size {
		return 0, io.EOF
	}
	n := len(p)
	if remaining := z.size - off; int64(n) > remaining {
		n = int(remaining)
	}
	clear(p[:n])
	return n, nil
}

// TestEncodeUDIFPeakHeapBounded is why any of this exists: encoding an image
// far larger than memory must cost a fixed amount of it.
//
// GC is disabled for the measurement, so the TotalAlloc delta is the peak heap
// rather than a figure the collector has already trimmed. Before the Reader
// field this test could not even be written — the API demanded a []byte, so an
// 8 GiB image needed 8 GiB.
func TestEncodeUDIFPeakHeapBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the heap-bound test in short mode")
	}

	const imageSize = 8 << 30 // 8 GiB, virtual
	const bound = 128 << 20   // generous: the real figure is a few MB

	old := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(old) })

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	err := EncodeUDIF(io.Discard, []SourceBlock{{
		Name:        "whole disk",
		SectorCount: imageSize / sectorSize,
		Reader:      zeroReaderAt{size: imageSize},
	}}, nil)
	if err != nil {
		t.Fatalf("EncodeUDIF: %v", err)
	}

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("encoding a %d GiB image allocated %d KiB", imageSize>>30, allocated>>10)

	if allocated > bound {
		t.Errorf("encoding allocated %d MiB, want under %d MiB; the image is being held rather than streamed",
			allocated>>20, bound>>20)
	}
}
