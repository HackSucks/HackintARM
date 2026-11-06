package disk

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lzfse"
)

func TestDMGLimits(t *testing.T) {
	image := make([]byte, 2<<20)
	copy(image, []byte("bounded image"))
	file := filepath.Join(t.TempDir(), "image.dmg")
	if err := WrapRawImageDMG(file, image, "Apple_APFS", nil); err != nil {
		t.Fatal(err)
	}
	for _, limits := range []DMGLimits{{ImageBytes: 1 << 20}, {MetadataBytes: 10}, {ChunkBytes: 1024}} {
		if r, err := OpenDMGWithLimits(file, limits); err == nil {
			r.Close()
			t.Fatalf("accepted %+v", limits)
		}
	}
	r, err := OpenDMGWithLimits(file, DMGLimits{ImageBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got := make([]byte, len(image))
	if _, err := r.ReadAt(got, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Equal(got, image) {
		t.Fatal("changed bytes")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, off := range []int{216, 224, 492} {
		bad := bytes.Clone(b)
		binary.BigEndian.PutUint64(bad[len(b)-512+off:], ^uint64(0))
		p := filepath.Join(t.TempDir(), "bad.dmg")
		if err := os.WriteFile(p, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if r, err := OpenDMG(p); err == nil {
			r.Close()
			t.Fatal("oversized metadata accepted", off)
		}
	}
}

func TestDecompressedChunkCannotExceedDeclaration(t *testing.T) {
	var encoded bytes.Buffer
	z := zlib.NewWriter(&encoded)
	if _, err := z.Write(bytes.Repeat([]byte{'x'}, 1<<20)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "chunk")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(encoded.Bytes()); err != nil {
		t.Fatal(err)
	}
	r := &DMGReader{reader: f}
	if _, err := r.decompressChunk(&DMGChunk{Type: chunkTypeCompressZLIB, DiskLength: 512, CompressedLength: uint64(encoded.Len())}); err == nil {
		t.Fatal("decompression bomb accepted")
	}
	if _, err := r.decompressChunk(&DMGChunk{Type: chunkTypeZeroFill, DiskLength: 1 << 40}); err == nil {
		t.Fatal("oversized allocation accepted")
	}
}

func TestLZFSEDeclaredOutputBounds(t *testing.T) {
	data := bytes.Repeat([]byte("application bytes"), 1024)
	encoded, err := lzfse.Compress(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkLZFSESize(encoded, uint64(len(data))); err != nil {
		t.Fatal(err)
	}
	if err := checkLZFSESize(encoded, 1); err == nil {
		t.Fatal("output limit ignored")
	}
	for _, b := range [][]byte{nil, []byte("bvx$"), []byte("bvx-"), []byte("unknown!"), []byte("bvxn\x00\x00\x00\x00"), []byte("bvx1\x00\x00\x00\x00"), []byte("bvx2\x00\x00\x00\x00")} {
		if err := checkLZFSESize(b, 100); err == nil {
			t.Fatalf("accepted %q", b)
		}
	}
	for _, magic := range []string{"bvx-", "bvxn", "bvx1", "bvx2"} {
		b := make([]byte, 800)
		copy(b, magic)
		binary.LittleEndian.PutUint32(b[4:], ^uint32(0))
		if err := checkLZFSESize(b, 1<<20); err == nil {
			t.Fatal("oversized block", magic)
		}
	}
}
