package lz4

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
)

type nativeBuffer struct {
	Name           string
	Plain, Encoded []byte
}
type nativeDecoder struct {
	Buffer, Variant, DecodedSHA256 string
	Capacity, Count                int
}

func corpus(t testing.TB) ([]nativeBuffer, []nativeDecoder) {
	t.Helper()
	f, e := os.Open("../../../testdata/appledouble/native/compression-lz4.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var c struct {
		Schema   int
		Buffers  []nativeBuffer
		Decoders []nativeDecoder
		Sources  map[string]string
	}
	if e = json.NewDecoder(z).Decode(&c); e != nil {
		t.Fatal(e)
	}
	if c.Schema != 1 || len(c.Buffers) != 140 || len(c.Decoders) != 900 {
		t.Fatal("incomplete native LZ4 corpus")
	}
	referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../../.."), c.Sources)
	if referenceErr != nil {
		t.Fatal(referenceErr)
	}
	if err := captureprovenance.Verify(referenceSources, c.Sources); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"scripts/capture-compression-lz4.go", "testdata/appledouble/native/compression-lz4.c", "testdata/appledouble/native/decmpfs-formats.c", "go.mod", "go.sum"} {
		b, e := captureprovenance.ReadSource(referenceSources, c.Sources, p)
		if e != nil {
			t.Fatal(e)
		}
		if fmt.Sprintf("%x", sha256.Sum256(b)) != c.Sources[p] {
			t.Fatalf("stale native source %s", p)
		}
	}
	return c.Buffers, c.Decoders
}
func TestNativeLZ4Buffers(t *testing.T) {
	buffers, _ := corpus(t)
	for _, c := range buffers {
		t.Run(c.Name, func(t *testing.T) {
			for _, extra := range []int{0, 1} {
				dst := make([]byte, len(c.Plain)+extra)
				reader := &boundedReader{t: t, data: c.Encoded}
				n, e := DecompressReader(dst, reader, int64(len(c.Encoded)))
				if e != nil || n != len(c.Plain) || !bytes.Equal(dst[:n], c.Plain) {
					t.Fatalf("n=%d err=%v", n, e)
				}
			}
		})
	}
}

type boundedReader struct {
	t    *testing.T
	data []byte
}

func (r *boundedReader) ReadAt(p []byte, at int64) (int, error) {
	if len(p) > 32768 {
		r.t.Fatalf("unbounded read: %d", len(p))
	}
	return bytes.NewReader(r.data).ReadAt(p, at)
}
func TestNativeLZ4DecoderCapacities(t *testing.T) {
	buffers, cases := corpus(t)
	byName := map[string]nativeBuffer{}
	for _, b := range buffers {
		byName[b.Name] = b
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/%s/%d", c.Buffer, c.Variant, c.Capacity), func(t *testing.T) {
			b, ok := byName[c.Buffer]
			if !ok {
				t.Fatal("unknown buffer reference")
			}
			src := append([]byte(nil), b.Encoded...)
			switch c.Variant {
			case "full":
			case "no-end":
				src = src[:len(src)-4]
			case "wrong-end":
				copy(src[len(src)-4:], "oops")
			case "truncated-body":
				src = src[:len(src)-5]
			case "trailing":
				src = append(src, []byte("ignored trailing data")...)
			default:
				t.Fatal("unknown variant")
			}
			dst := make([]byte, c.Capacity)
			n, e := DecompressInto(dst, src)
			actual := n
			if e != nil {
				actual = 0
			}
			if actual != c.Count || fmt.Sprintf("%x", sha256.Sum256(dst[:actual])) != c.DecodedSHA256 {
				t.Fatalf("native count=%d Go=%d err=%v", c.Count, n, e)
			}
			if actual > len(b.Plain) || !bytes.Equal(dst[:actual], b.Plain[:actual]) {
				t.Fatal("native prefix differs")
			}
		})
	}
}
