package disk

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"
)

// TestKolyFooterSize guards the on-disk invariant that the koly trailer is
// exactly 512 bytes.
func TestKolyFooterSize(t *testing.T) {
	if got := binary.Size(DMGFooter{}); got != dmgFooterSize {
		t.Fatalf("DMGFooter size = %d, want %d", got, dmgFooterSize)
	}
}

// buildSyntheticImage produces a multi-MB raw image mixing zero regions,
// random regions and repeated patterns so the encoder exercises zero-fill,
// zlib and raw chunk paths.
func buildSyntheticImage() []byte {
	const size = 6 << 20 // 6 MiB, sector-aligned
	img := make([]byte, size)
	rng := rand.New(rand.NewSource(0xA9F5))

	// [0, 1MiB): random (incompressible -> raw chunks)
	rng.Read(img[0 : 1<<20])
	// [1MiB, 3MiB): left as zeros (zero-fill chunks)
	// [3MiB, 4MiB): repeated pattern (compresses well -> zlib chunks)
	for i := 3 << 20; i < 4<<20; i++ {
		img[i] = byte(i % 251)
	}
	// [4MiB, 5MiB): mostly zeros with a few sparse non-zero bytes
	for i := 4 << 20; i < 5<<20; i += 4096 {
		img[i] = 0x5A
	}
	// [5MiB, 6MiB): random again
	rng.Read(img[5<<20 : 6<<20])

	return img
}

// TestEncodeDecodeSyntheticImage encodes a synthetic raw image to a UDIF DMG
// and reconstructs it, asserting byte-identical round-trip. Runs on every OS
// with no external dependencies.
func TestEncodeDecodeSyntheticImage(t *testing.T) {
	img := buildSyntheticImage()

	for _, tc := range []struct {
		name string
		opts *EncodeOptions
	}{
		{"zlib", &EncodeOptions{Compression: CompressionZlib}},
		{"none", &EncodeOptions{Compression: CompressionNone}},
		{"nochecksum", &EncodeOptions{Compression: CompressionZlib, NoChecksums: true}},
		{"smallchunks", &EncodeOptions{Compression: CompressionZlib, ChunkSectors: 128}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blocks := []SourceBlock{{
				Name:        "disk image (Apple_APFS : 0)",
				StartSector: 0,
				Data:        img,
			}}

			var buf bytes.Buffer
			if err := EncodeUDIF(&buf, blocks, tc.opts); err != nil {
				t.Fatalf("EncodeUDIF: %v", err)
			}

			dst := filepath.Join(t.TempDir(), "synthetic.dmg")
			if err := os.WriteFile(dst, buf.Bytes(), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}

			got, err := ReconstructRawImage(dst)
			if err != nil {
				t.Fatalf("ReconstructRawImage: %v", err)
			}

			if len(got) != len(img) {
				t.Fatalf("length mismatch: got %d want %d", len(got), len(img))
			}
			if sha256.Sum256(got) != sha256.Sum256(img) {
				t.Fatalf("content mismatch after round-trip")
			}
			t.Logf("encoded %d bytes -> DMG %d bytes", len(img), buf.Len())
		})
	}
}

// TestBuffersNeededMatchesHdiutil checks every block's BuffersNeeded against
// the rule measured from hdiutil's own images: a chunk plus 8 sectors for zlib
// and raw images, and a chunk plus the image's largest compressed chunk for
// LZFSE and LZMA, recorded in every block alike.
func TestBuffersNeededMatchesHdiutil(t *testing.T) {
	img := buildSyntheticImage()
	tail := bytes.Repeat([]byte("a small, compressible block "), 1024)[:32*sectorSize]
	for _, tc := range []struct {
		name string
		opts *EncodeOptions
	}{
		{"zlib", &EncodeOptions{Compression: CompressionZlib}},
		{"none", &EncodeOptions{Compression: CompressionNone}},
		{"lzfse", &EncodeOptions{Compression: CompressionLZFSE}},
		{"lzma", &EncodeOptions{Compression: CompressionLZMA}},
		{"lzfse smallchunks", &EncodeOptions{Compression: CompressionLZFSE, ChunkSectors: 128}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blocks := []SourceBlock{
				{Name: "disk image (Apple_HFS : 0)", Data: img},
				{Name: "tail", StartSector: uint64(len(img)) / sectorSize, Data: tail},
			}
			var buf bytes.Buffer
			if err := EncodeUDIF(&buf, blocks, tc.opts); err != nil {
				t.Fatalf("EncodeUDIF: %v", err)
			}
			r, err := NewDMGReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()), DMGLimits{})
			if err != nil {
				t.Fatalf("NewDMGReader: %v", err)
			}
			chunkSectors := cmp.Or(tc.opts.ChunkSectors, encodeDefaultChunkSectors)
			want := uint32(chunkSectors) + 8
			if tc.opts.Compression == CompressionLZFSE || tc.opts.Compression == CompressionLZMA {
				var largest uint64
				for _, partition := range r.Partitions() {
					for _, chunk := range partition.Chunks {
						if chunk.Type == chunkTypeCompressLZFSE || chunk.Type == chunkTypeCompressLZMA {
							largest = max(largest, chunk.CompressedLength)
						}
					}
				}
				want = uint32(chunkSectors + (largest+sectorSize-1)/sectorSize)
			}
			var document dmgPlist
			if _, err := plist.Unmarshal(buf.Bytes()[r.footer.PlistOffset:r.footer.PlistOffset+r.footer.PlistLength], &document); err != nil {
				t.Fatalf("plist: %v", err)
			}
			for _, block := range document.ResourceFork.Blkx {
				var header dmgBlockData
				if err := binary.Read(bytes.NewReader(block.Data), binary.BigEndian, &header); err != nil {
					t.Fatalf("block header: %v", err)
				}
				if header.BuffersNeeded != want {
					t.Fatalf("block %q BuffersNeeded = %d, want %d", block.Name, header.BuffersNeeded, want)
				}
			}
		})
	}
}

// TestEncodeMultiBlock verifies that multiple blocks at distinct sector ranges
// reconstruct into the correct absolute layout.
func TestEncodeMultiBlock(t *testing.T) {
	a := bytes.Repeat([]byte{0x11}, 512)       // 1 sector
	b := make([]byte, 4*512)                   // 4 zero sectors
	c := bytes.Repeat([]byte{0x22, 0x33}, 512) // 2 sectors

	blocks := []SourceBlock{
		{Name: "a", StartSector: 0, Data: a},
		{Name: "b", StartSector: 1, Data: b},
		{Name: "c", StartSector: 5, Data: c},
	}

	var buf bytes.Buffer
	if err := EncodeUDIF(&buf, blocks, nil); err != nil {
		t.Fatalf("EncodeUDIF: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "multi.dmg")
	if err := os.WriteFile(dst, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	raw, err := ReconstructRawImage(dst)
	if err != nil {
		t.Fatalf("ReconstructRawImage: %v", err)
	}

	want := make([]byte, 7*512)
	copy(want[0:], a)
	copy(want[5*512:], c)
	if !bytes.Equal(raw, want) {
		t.Fatalf("multi-block reconstruction mismatch")
	}
}

// TestRepackRoundTrip is gated on DMG_REPACK_SRC. It reconstructs the raw image
// from a source DMG, repacks it, reconstructs the raw image from the repack,
// and asserts the raw images are byte-identical. It also opens the repacked DMG
// through the normal reader path to prove it is still openable.
func TestRepackRoundTrip(t *testing.T) {
	src := os.Getenv("DMG_REPACK_SRC")
	if src == "" {
		t.Skip("set DMG_REPACK_SRC to a source DMG to run this test")
	}

	rawOrig, err := ReconstructRawImage(src)
	if err != nil {
		t.Fatalf("reconstruct source: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "repacked.dmg")
	if err := RepackDMG(src, dst, nil); err != nil {
		t.Fatalf("RepackDMG: %v", err)
	}

	rawRepack, err := ReconstructRawImage(dst)
	if err != nil {
		t.Fatalf("reconstruct repack: %v", err)
	}

	if len(rawOrig) != len(rawRepack) {
		t.Fatalf("raw length differs: orig %d, repack %d", len(rawOrig), len(rawRepack))
	}
	if sha256.Sum256(rawOrig) != sha256.Sum256(rawRepack) {
		t.Fatalf("raw sha256 differs after repack")
	}

	srcInfo, _ := os.Stat(src)
	dstInfo, _ := os.Stat(dst)
	t.Logf("raw round-trip OK: %d bytes; original DMG %d, repacked DMG %d", len(rawOrig), srcInfo.Size(), dstInfo.Size())

	// Prove the repacked DMG opens through the standard reader path and that
	// the file system signature is present at the partition start.
	reader, off, closer, err := OpenWithOffset(dst)
	if err != nil {
		t.Fatalf("OpenWithOffset(repack): %v", err)
	}
	defer closer.Close()

	sig := make([]byte, 2048)
	if _, err := reader.ReadAt(sig, off); err != nil {
		t.Fatalf("read partition head: %v", err)
	}
	// APFS container: "NXSB" at 32; HFS+/HFSX volume header: "H+"/"HX" at 1024.
	isAPFS := string(sig[32:36]) == "NXSB"
	isHFS := string(sig[1024:1026]) == "H+" || string(sig[1024:1026]) == "HX"
	if !isAPFS && !isHFS {
		t.Fatalf("no APFS/HFS+ signature at partition start of repacked DMG")
	}
	t.Logf("repacked DMG opens via reader (apfs=%v hfs=%v)", isAPFS, isHFS)
}
