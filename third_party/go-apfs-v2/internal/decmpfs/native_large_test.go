package decmpfs

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
)

type nativeLargeCase struct {
	Name, Origin, SHA256, ForkSHA256 string
	StoredCompressed                 bool
	Type                             uint32
	Size                             int64
	Attribute                        []byte
}
type nativeLargeSource struct {
	*os.File
	size    uint64
	maximum int
}

func (s *nativeLargeSource) Size() uint64 { return s.size }
func (s *nativeLargeSource) ReadAt(p []byte, at int64) (int, error) {
	s.maximum = max(s.maximum, len(p))
	return s.File.ReadAt(p, at)
}

func TestLargeCompressionNativeRanges(t *testing.T) {
	const dir = "../../testdata/appledouble/native/large-compression"
	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Sources map[string]string
		Cases   []nativeLargeCase
	}
	if err = json.Unmarshal(manifest, &corpus); err != nil {
		t.Fatal(err)
	}
	referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), corpus.Sources)
	if referenceErr != nil {
		t.Fatal(referenceErr)
	}
	if err := captureprovenance.Verify(referenceSources, corpus.Sources); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"scripts/verify-large-compression.go", "testdata/appledouble/native/decmpfs-large.c", "testdata/appledouble/native/decmpfs-expand.c"} {
		b, err := captureprovenance.ReadSource(referenceSources, corpus.Sources, path)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != corpus.Sources[path] {
			t.Fatalf("native capture is stale for %s", path)
		}
	}
	if len(corpus.Cases) != 43 {
		t.Fatalf("native inventory: %d", len(corpus.Cases))
	}
	seen := map[string]bool{}
	compressed := 0
	for _, c := range corpus.Cases {
		if seen[c.Name] {
			t.Fatalf("duplicate native case %s", c.Name)
		}
		seen[c.Name] = true
		if !c.StoredCompressed {
			if c.Name != "native-4-536870913" || c.ForkSHA256 != "" || len(c.Attribute) != 0 {
				t.Fatalf("unexpected uncompressed control: %+v", c)
			}
			continue
		}
		compressed++
		t.Run(c.Name, func(t *testing.T) {
			if len(c.Attribute) != HeaderSize || !bytes.Equal(c.Attribute[:4], HeaderSignature[:]) || binary.LittleEndian.Uint32(c.Attribute[4:]) != c.Type || binary.LittleEndian.Uint64(c.Attribute[8:]) != uint64(c.Size) {
				t.Fatal("native attribute differs from manifest")
			}
			archive, err := os.Open(filepath.Join(dir, c.Name+".fork.gz"))
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			z, err := gzip.NewReader(archive)
			if err != nil {
				t.Fatal(err)
			}
			defer z.Close()
			fork, err := os.CreateTemp(t.TempDir(), "fork-")
			if err != nil {
				t.Fatal(err)
			}
			defer fork.Close()
			hash := sha256.New()
			size, err := io.Copy(io.MultiWriter(fork, hash), z)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(hash.Sum(nil)) != c.ForkSHA256 {
				t.Fatal("retained native fork checksum differs")
			}
			method, err := MethodFor(c.Type)
			if err != nil {
				t.Fatal(err)
			}
			source := &nativeLargeSource{File: fork, size: uint64(size)}
			h, err := NewHandle(source, uint64(c.Size), method)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			for _, offset := range []int64{0, BlockSize - 9, c.Size / 2, c.Size - 129, c.Size - 1} {
				if offset < 0 || offset >= c.Size {
					t.Fatal("invalid range recipe")
				}
				if _, err = h.SeekSegmentOffset(0, offset); err != nil {
					t.Fatal(err)
				}
				p := make([]byte, min(int64(257), c.Size-offset))
				n, err := h.ReadSegmentData(0, p)
				if err != nil || n != len(p) {
					t.Fatalf("read at %d: n=%d err=%v", offset, n, err)
				}
				for i, b := range p {
					at := (offset + int64(i)) % BlockSize
					if b != "ABCDEFGHIJKLMNOPQRSTUVWXYZ "[at%27] {
						t.Fatalf("logical byte differs at %d", offset+int64(i))
					}
				}
			}
			if source.maximum > BlockSize+1 {
				t.Fatalf("unbounded source read: %d", source.maximum)
			}
			if c.Size >= 1<<30 && h.largeIndex == nil {
				t.Fatal("large native table was materialized")
			}
		})
	}
	if compressed != 42 {
		t.Fatalf("compressed native inventory: %d", compressed)
	}
}
