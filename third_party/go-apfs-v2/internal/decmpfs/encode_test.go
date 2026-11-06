package decmpfs

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type encodeBuffer []byte

func (b encodeBuffer) WriteAt(p []byte, at int64) (int, error) { return copy(b[at:], p), nil }
func TestEncodeForkNativeBytes(t *testing.T) {
	f, e := os.Open("../../testdata/appledouble/native/compression-writer.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var corpus struct {
		Cases []struct {
			Name                   string
			Requested              uint32
			Plain, Attribute, Fork []byte
		}
	}
	if e = json.NewDecoder(z).Decode(&corpus); e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, c := range corpus.Cases {
		if len(c.Fork) == 0 {
			continue
		}
		count++
		t.Run(fmt.Sprintf("%d/%s", c.Requested, c.Name), func(t *testing.T) {
			target := make(encodeBuffer, len(c.Plain)+4096)
			result, e := EncodeFork(t.Context(), bytes.NewReader(c.Plain), int64(len(c.Plain)), c.Requested, target)
			if e != nil {
				t.Fatal(e)
			}
			method, err := MethodFor(c.Requested)
			if err != nil {
				t.Fatal(err)
			}
			h, err := NewHandle(&memSource{data: c.Fork}, uint64(len(c.Plain)), method)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			decoded := make([]byte, len(c.Plain))
			for at := 0; at < len(decoded); {
				p := decoded[at:min(len(decoded), at+4331)]
				n, err := h.ReadSegmentData(0, p)
				if err != nil || n != len(p) {
					t.Fatalf("native fork readback at %d: %d %v", at, n, err)
				}
				at += n
			}
			if !bytes.Equal(decoded, c.Plain) {
				t.Fatal("native fork logical bytes differ")
			}
			if !bytes.Equal(result.Attribute[:], c.Attribute) || !bytes.Equal(target[:result.Size], c.Fork) {
				for at := 0; at < min(int(result.Size), len(c.Fork)); at++ {
					if target[at] != c.Fork[at] {
						t.Logf("first difference at %d: got=%x want=%x", at, target[at:min(at+40, int(result.Size))], c.Fork[at:min(at+40, len(c.Fork))])
						break
					}
				}
				t.Fatalf("native bytes differ: kind=%d actual size=%d expected=%d header=%x/%x", c.Requested, result.Size, len(c.Fork), result.Attribute, c.Attribute)
			}
		})
	}
	if count != 592 {
		t.Fatal("incomplete native output cases", count)
	}
}
