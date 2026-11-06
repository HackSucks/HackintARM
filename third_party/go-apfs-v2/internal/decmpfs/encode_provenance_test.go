package decmpfs

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
)

func TestNativeEncoderProvenance(t *testing.T) {
	for _, c := range []struct {
		fixture string
		sources []string
	}{
		{"compression-lz4-macos26.json.gz", []string{"testdata/appledouble/native/compression-lz4.c", "testdata/appledouble/native/decmpfs-formats.c", "scripts/capture-compression-lz4.go", "go.mod", "go.sum"}},
		{"compression-query-macos26.json.gz", []string{"testdata/appledouble/native/compression-query.c", "testdata/appledouble/native/compression-policy.c", "scripts/capture-compression-query.go", "internal/testutil/diskimage/attachment.go", "internal/testutil/diskimage/detach.go", "go.mod", "go.sum"}},
		{"compression-blocks.json.gz", []string{"testdata/appledouble/native/compression-blocks.c", "scripts/capture-compression-blocks.go"}},
		{"compression-policy.json.gz", []string{"testdata/appledouble/native/compression-policy.c", "scripts/capture-compression-policy.go", "go.mod", "go.sum"}},
		{"compression-writer.json.gz", []string{"testdata/appledouble/native/decmpfs-large.c", "scripts/capture-compression-writer.go", "go.mod", "go.sum"}},
		{"compression-zlib-source.json", []string{"testdata/appledouble/native/compression-zlib-source.c", "scripts/verify-compression-zlib-source.go"}},
	} {
		t.Run(c.fixture, func(t *testing.T) {
			f, err := os.Open(filepath.Join("../../testdata/appledouble/native", c.fixture))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var input io.Reader = f
			if filepath.Ext(c.fixture) == ".gz" {
				z, err := gzip.NewReader(f)
				if err != nil {
					t.Fatal(err)
				}
				defer z.Close()
				input = z
			}
			var record struct {
				Host, Compiler, SDK string
				Sources             map[string]string
			}
			if err := json.NewDecoder(input).Decode(&record); err != nil {
				t.Fatal(err)
			}
			if record.Host == "" || record.Compiler == "" || record.SDK == "" {
				t.Fatal("missing native host/compiler/SDK evidence")
			}
			referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), record.Sources)
			if referenceErr != nil {
				t.Fatal(referenceErr)
			}
			if err := captureprovenance.Verify(referenceSources, record.Sources); err != nil {
				t.Fatal(err)
			}
			for _, path := range c.sources {
				b, err := captureprovenance.ReadSource(referenceSources, record.Sources, path)
				if err != nil {
					t.Fatal(err)
				}
				if got := fmt.Sprintf("%x", sha256.Sum256(b)); record.Sources[path] != got {
					t.Fatalf("stale native capture: %s", path)
				}
			}
		})
	}
}

func TestNativeCompressionTypeSelection(t *testing.T) {
	f, err := os.Open("../../testdata/appledouble/native/compression-writer.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var corpus struct {
		Selections []struct {
			Requested              uint32
			Accepted               bool
			Flags                  uint32
			Size                   int64
			Plain, Attribute, Fork []byte
		}
	}
	if err := json.NewDecoder(z).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Selections) != 33 {
		t.Fatal("incomplete native type selection audit")
	}
	for i, c := range corpus.Selections {
		t.Run(fmt.Sprint(c.Requested), func(t *testing.T) {
			if c.Requested != uint32(i) || !c.Accepted || c.Flags&32 == 0 || c.Size != 65536 || len(c.Attribute) != 16 {
				t.Fatal("invalid native selection control")
			}
			actual := binary.LittleEndian.Uint32(c.Attribute[4:8])
			expected := uint32(8)
			if c.Requested >= 3 && c.Requested <= 14 && c.Requested != 5 && c.Requested != 6 {
				expected = (c.Requested + 1) &^ 1
			}
			if actual != expected {
				t.Fatalf("native selector %d produced type %d, expected %d", c.Requested, actual, expected)
			}
			target := make(encodeBuffer, len(c.Plain)+4096)
			result, err := EncodeFork(t.Context(), bytes.NewReader(c.Plain), int64(len(c.Plain)), actual, target)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(result.Attribute[:], c.Attribute) || !bytes.Equal(target[:result.Size], c.Fork) {
				t.Fatal("selected native storage differs")
			}
		})
	}
}
