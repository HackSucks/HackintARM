package decmpfs

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestEncodeZlibNativeBlocks(t *testing.T) {
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
		if c.Requested != 4 || len(c.Fork) == 0 {
			continue
		}
		count++
		blocks := int(binary.LittleEndian.Uint32(c.Fork[260:264]))
		for i := 0; i < blocks; i++ {
			t.Run(fmt.Sprintf("%s/%d", c.Name, i), func(t *testing.T) {
				at := 264 + 8*i
				offset := int(binary.LittleEndian.Uint32(c.Fork[at:])) + 260
				length := int(binary.LittleEndian.Uint32(c.Fork[at+4:]))
				want := c.Fork[offset : offset+length]
				plain := c.Plain[i*BlockSize : min((i+1)*BlockSize, len(c.Plain))]
				got := encodeZlibBlock(plain)
				if len(plain) != 1 && len(got) >= len(plain) {
					got = append([]byte{0xff}, plain...)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("native zlib mismatch: got length=%d prefix=%x; want length=%d prefix=%x", len(got), got[:min(len(got), 32)], len(want), want[:min(len(want), 32)])
				}
			})
		}
	}
	if count != 59 {
		t.Fatal("incomplete native zlib corpus", count)
	}
}

func TestEncodeZlibNativeBufferCorpus(t *testing.T) {
	f, err := os.Open("../../testdata/appledouble/native/compression-blocks.json.gz")
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
		Cases []struct {
			Name           string
			Algorithm      uint32
			Plain, Encoded []byte
		}
	}
	if err = json.NewDecoder(z).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, c := range corpus.Cases {
		if c.Algorithm != 0x205 {
			continue
		}
		count++
		t.Run(c.Name, func(t *testing.T) {
			got := encodeZlibBlock(c.Plain)
			if !bytes.Equal(got[2:], c.Encoded) {
				at := 0
				for at < min(len(got)-2, len(c.Encoded)) && got[at+2] == c.Encoded[at] {
					at++
				}
				t.Fatalf("native output differs: got=%d native=%d first=%d", len(got)-2, len(c.Encoded), at)
			}
		})
	}
	if count != 366 {
		t.Fatal("incomplete native zlib corpus", count)
	}
}

// Destination-capacity observations qualify the filesystem fallback independently
// of the whole-fork fixtures. The two-byte zlib wrapper consumes native capacity;
// the one-byte underflow case is retained in the whole-fork corpus.
func TestEncodeBlockNativeStoredFallback(t *testing.T) {
	f, err := os.Open("../../testdata/appledouble/native/compression-blocks.json.gz")
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
		Cases []struct {
			Name           string
			Algorithm      uint32
			Plain, Encoded []byte
		}
		Bounded []struct {
			Input, Capacity int
			Encoded         []byte
		}
	}
	if err := json.NewDecoder(z).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	counts := map[uint32]int{}
	for _, b := range corpus.Bounded {
		if b.Input < 0 || b.Input >= len(corpus.Cases) {
			t.Fatal("invalid bounded input")
		}
		c := corpus.Cases[b.Input]
		kind, marker, capacity := uint32(0), byte(0xff), len(c.Plain)
		switch c.Algorithm {
		case 0x205:
			kind = 4
			capacity -= 2
		case 0x900:
			kind = 8
			marker = 6
		case 0x801:
			kind = 12
		case 0x702:
			kind = 14
		default:
			continue
		}
		if capacity < 0 || b.Capacity != capacity || len(c.Plain) > BlockSize {
			continue
		}
		counts[kind]++
		t.Run(fmt.Sprintf("%d/%s", kind, c.Name), func(t *testing.T) {
			want := bytes.Clone(b.Encoded)
			if len(want) == 0 {
				want = append([]byte{marker}, c.Plain...)
			} else if kind == 4 {
				want = append([]byte{0x78, 0x5e}, want...)
			}
			got, err := encodeBlock(c.Plain, kind)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("native filesystem block differs: got %d bytes, native %d", len(got), len(want))
			}
		})
	}
	for kind, want := range map[uint32]int{4: 79, 8: 85, 12: 85, 14: 86} {
		if counts[kind] != want {
			t.Fatalf("type %d inventory: %d want %d", kind, counts[kind], want)
		}
	}
}
