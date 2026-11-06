package lzbitmap

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestEncodeNativeBufferCorpus(t *testing.T) {
	f, err := os.Open("../../../testdata/appledouble/native/compression-blocks.json.gz")
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
		Bounded []struct {
			Input, Capacity int
			Encoded         []byte
		}
		Cases []struct {
			Name           string
			Algorithm      uint32
			Plain, Encoded []byte
		}
	}
	if err := json.NewDecoder(z).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, c := range corpus.Cases {
		if c.Algorithm != 0x702 {
			continue
		}
		count++
		t.Run(c.Name, func(t *testing.T) {
			got, err := Compress(c.Plain)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, c.Encoded) {
				t.Fatalf("native encoding mismatch: got %d bytes, native %d", len(got), len(c.Encoded))
			}
			plain, err := Decompress(c.Encoded)
			if err != nil || !bytes.Equal(plain, c.Plain) {
				t.Fatalf("native decoding mismatch: %v", err)
			}
		})
	}
	bounded := 0
	for _, b := range corpus.Bounded {
		if b.Input < 0 || b.Input >= len(corpus.Cases) {
			t.Fatal("invalid bounded input")
		}
		c := corpus.Cases[b.Input]
		if c.Algorithm != 0x702 {
			continue
		}
		bounded++
		t.Run(fmt.Sprintf("%s/capacity%d", c.Name, b.Capacity), func(t *testing.T) {
			dst := make([]byte, b.Capacity)
			n := EncodeBuffer(dst, c.Plain)
			if n != len(b.Encoded) || !bytes.Equal(dst[:n], b.Encoded) {
				t.Fatalf("native bounded encoding differs: got %d native %d capacity %d", n, len(b.Encoded), b.Capacity)
			}
		})
	}
	if bounded != 1413 {
		t.Fatalf("incomplete bounded inventory: %d", bounded)
	}
	if count != 407 {
		t.Fatalf("incomplete native corpus: %d", count)
	}
}
