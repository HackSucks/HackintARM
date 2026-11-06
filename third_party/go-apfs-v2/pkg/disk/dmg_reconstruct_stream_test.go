package disk

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
)

// buildFixtureDMG writes a DMG whose raw image is img and returns its path.
func buildFixtureDMG(t *testing.T, img []byte, opts *EncodeOptions) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.dmg")
	if err := WrapRawImageDMG(path, img, "Apple_APFS", opts); err != nil {
		t.Fatalf("building the fixture DMG: %v", err)
	}
	return path
}

// TestBlockReaderMatchesTheMaterialisedImage checks reading a block lazily
// yields exactly what materialising it did, including the gaps: chunks are not
// guaranteed to tile a block, and anything they do not cover must read as zeros.
func TestBlockReaderMatchesTheMaterialisedImage(t *testing.T) {
	img := streamTestImage(encodeDefaultChunkSectors * sectorSize)
	dmg := buildFixtureDMG(t, img, nil)

	blocks, _, closer, err := reconstructBlocks(dmg)
	if err != nil {
		t.Fatalf("reconstructBlocks: %v", err)
	}
	defer closer.Close()

	if len(blocks) != 1 {
		t.Fatalf("got %d blocks, want 1", len(blocks))
	}
	block := blocks[0]
	if block.Reader == nil {
		t.Fatal("the block was materialised rather than made lazy")
	}
	if block.Data != nil {
		t.Error("the block carries Data as well as a Reader")
	}

	// Read it whole.
	whole := make([]byte, block.SectorCount*sectorSize)
	if _, err := readFullAt(block.Reader, whole, 0); err != nil {
		t.Fatalf("reading the block: %v", err)
	}
	if !bytes.Equal(whole, img) {
		t.Error("reading the block whole did not reproduce the source image")
	}

	// Read it in awkward pieces: unaligned offsets and lengths that straddle
	// chunk boundaries are exactly where an offset error hides.
	for _, span := range []struct{ off, length int64 }{
		{0, 1},
		{1, 4095},
		{int64(len(img)) / 2, 8192},
		{int64(len(img)) - 512, 512},
		{4096, int64(len(img)) - 8192},
	} {
		got := make([]byte, span.length)
		if _, err := readFullAt(block.Reader, got, span.off); err != nil {
			t.Fatalf("reading %d bytes at %d: %v", span.length, span.off, err)
		}
		if !bytes.Equal(got, img[span.off:span.off+span.length]) {
			t.Errorf("reading %d bytes at %d did not match the source", span.length, span.off)
		}
	}

	// Past the end must report EOF rather than zeros.
	if _, err := block.Reader.ReadAt(make([]byte, 16), int64(len(img))); err != io.EOF {
		t.Errorf("reading past the end returned %v, want io.EOF", err)
	}
}

// TestBlockReaderRandomAccess checks the single-chunk cache does not corrupt
// out-of-order reads. The encoder reads ascending, but nothing in the type
// promises that, and a cache that assumed it would be a subtle disaster.
func TestBlockReaderRandomAccess(t *testing.T) {
	img := streamTestImage(encodeDefaultChunkSectors * sectorSize)
	dmg := buildFixtureDMG(t, img, nil)

	blocks, _, closer, err := reconstructBlocks(dmg)
	if err != nil {
		t.Fatalf("reconstructBlocks: %v", err)
	}
	defer closer.Close()

	// Walk backwards, which defeats the cache on every read.
	const window = 4096
	for off := int64(len(img)) - window; off >= 0; off -= window * 7 {
		got := make([]byte, window)
		if _, err := readFullAt(blocks[0].Reader, got, off); err != nil {
			t.Fatalf("reading at %d: %v", off, err)
		}
		if !bytes.Equal(got, img[off:off+window]) {
			t.Fatalf("backwards read at %d did not match the source", off)
		}
	}
}

// TestRepackDMGIsUnchangedByLazyReading is the guarantee that matters: a repack
// must produce the same bytes now that it never materialises a block.
func TestRepackDMGIsUnchangedByLazyReading(t *testing.T) {
	img := streamTestImage(encodeDefaultChunkSectors * sectorSize)
	src := buildFixtureDMG(t, img, nil)
	dir := t.TempDir()

	// Repack lazily, as RepackDMG now does.
	lazy := filepath.Join(dir, "lazy.dmg")
	if err := RepackDMG(src, lazy, nil); err != nil {
		t.Fatalf("RepackDMG: %v", err)
	}

	// Repack the old way: materialise the image, then encode it from a slice.
	raw, err := ReconstructRawImage(src)
	if err != nil {
		t.Fatalf("ReconstructRawImage: %v", err)
	}
	blocks, _, closer, err := reconstructBlocks(src)
	if err != nil {
		t.Fatalf("reconstructBlocks: %v", err)
	}
	closer.Close()

	materialised := filepath.Join(dir, "materialised.dmg")
	block := blocks[0]
	block.Reader = nil
	block.Data = raw
	if err := encodeToFile(materialised, []SourceBlock{block}, nil); err != nil {
		t.Fatalf("encoding the materialised block: %v", err)
	}

	a, err := os.ReadFile(lazy)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(materialised)
	if err != nil {
		t.Fatal(err)
	}
	if sha256Of(a) != sha256Of(b) {
		t.Errorf("the lazy repack differs from the materialised one (%d vs %d bytes)", len(a), len(b))
	}

	// And it must still reconstruct to the original image.
	back, err := ReconstructRawImage(lazy)
	if err != nil {
		t.Fatalf("reconstructing the repacked DMG: %v", err)
	}
	if !bytes.Equal(back, img) {
		t.Error("the repacked DMG does not reconstruct to the source image")
	}
}

// TestReconstructRawImageToMatchesInMemory checks the streaming reconstruction
// agrees with the in-memory one, which the acceptance suite relies on.
func TestReconstructRawImageToMatchesInMemory(t *testing.T) {
	img := streamTestImage(encodeDefaultChunkSectors * sectorSize)
	dmg := buildFixtureDMG(t, img, nil)

	inMemory, err := ReconstructRawImage(dmg)
	if err != nil {
		t.Fatalf("ReconstructRawImage: %v", err)
	}
	if !bytes.Equal(inMemory, img) {
		t.Fatal("the in-memory reconstruction does not match the source image")
	}

	out := filepath.Join(t.TempDir(), "raw.img")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	total, err := ReconstructRawImageTo(f, dmg)
	if err != nil {
		f.Close()
		t.Fatalf("ReconstructRawImageTo: %v", err)
	}
	f.Close()

	if total != int64(len(img)) {
		t.Errorf("reported %d bytes, want %d", total, len(img))
	}
	streamed, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(streamed, img) {
		t.Error("the streamed reconstruction does not match the source image")
	}
}

// TestAllZeroImageRoundTrips guards a case that could not previously be built
// cheaply enough to notice: an image whose chunks are every one zero-fill
// writes no data fork, so its plist starts at offset zero — which the reader
// took for "no plist at all". A fully sparse image is exactly what a large
// repack produces.
func TestAllZeroImageRoundTrips(t *testing.T) {
	img := make([]byte, 64*sectorSize)
	dmg := buildFixtureDMG(t, img, nil)

	back, err := ReconstructRawImage(dmg)
	if err != nil {
		t.Fatalf("reconstructing an all-zero image: %v", err)
	}
	if !bytes.Equal(back, img) {
		t.Error("an all-zero image did not round-trip")
	}
}

// TestRepackDMGPeakHeapBounded is the point of the change: repacking a large
// DMG must not materialise it. A mostly-zero 2 GiB image makes a tiny DMG, so
// the fixture is cheap while the raw image it describes is not.
func TestRepackDMGPeakHeapBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the heap-bound test in short mode")
	}

	const imageSize = 2 << 30 // 2 GiB of raw image
	const bound = 128 << 20

	dir := t.TempDir()
	src := filepath.Join(dir, "sparse.dmg")
	if err := WrapRawImageDMGFrom(src, zeroReaderAt{size: imageSize}, imageSize, "Apple_APFS", nil); err != nil {
		t.Fatalf("building the sparse fixture: %v", err)
	}
	if info, err := os.Stat(src); err == nil {
		t.Logf("a %d GiB sparse image is a %d KiB DMG", imageSize>>30, info.Size()>>10)
	}

	old := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(old) })

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	if err := RepackDMG(src, filepath.Join(dir, "repacked.dmg"), nil); err != nil {
		t.Fatalf("RepackDMG: %v", err)
	}

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("repacking allocated %d KiB", allocated>>10)

	if allocated > bound {
		t.Errorf("repacking allocated %d MiB, want under %d MiB; the image is being materialised",
			allocated>>20, bound>>20)
	}
}
