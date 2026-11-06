package lzfse

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestNativeCompressionBufferCapacities(t *testing.T) {
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
		LegacyV1, LegacyV1Plain []byte
		Cases                   []struct {
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
	t.Run("native-accepted-legacy-v1", func(t *testing.T) {
		if len(corpus.LegacyV1) != 802 || !bytes.Equal(corpus.LegacyV1Plain, []byte("ab")) {
			t.Fatal("missing native legacy evidence")
		}
		plain, err := Decompress(corpus.LegacyV1)
		if err != nil || !bytes.Equal(plain, corpus.LegacyV1Plain) {
			t.Fatalf("legacy decode: %x %v", plain, err)
		}
		for n := 0; n < len(corpus.LegacyV1); n++ {
			if _, err := DecompressInto(make([]byte, 2), corpus.LegacyV1[:n]); err == nil {
				t.Fatalf("accepted legacy truncation %d", n)
			}
			if _, err := DecodedSize(corpus.LegacyV1[:n]); err == nil {
				t.Fatalf("accepted truncated legacy size %d", n)
			}
		}
		if _, err := DecompressInto(make([]byte, 1), corpus.LegacyV1); !errors.Is(err, ErrOutputFull) {
			t.Fatalf("output bound: %v", err)
		}
		for _, c := range []struct {
			name      string
			at, width int
			value     uint32
			want      error
		}{
			{"literals", 12, 4, 0xffffffff, ErrCorrupt}, {"matches", 16, 4, 0xffffffff, ErrCorrupt},
			{"literal-payload", 20, 4, 0xffffffff, ErrTruncated}, {"lmd-payload", 24, 4, 0xffffffff, ErrTruncated},
			{"literal-bits", 28, 4, 1, ErrCorrupt}, {"lmd-bits", 40, 4, 1, ErrCorrupt},
			{"literal-state0", 32, 2, 1024, ErrCorrupt}, {"literal-state1", 34, 2, 1024, ErrCorrupt},
			{"literal-state2", 36, 2, 1024, ErrCorrupt}, {"literal-state3", 38, 2, 1024, ErrCorrupt},
			{"l-state", 44, 2, 64, ErrCorrupt}, {"m-state", 46, 2, 64, ErrCorrupt}, {"d-state", 48, 2, 256, ErrCorrupt},
			{"l-frequency", 50, 2, 65, ErrCorrupt}, {"m-frequency", 90, 2, 65, ErrCorrupt},
			{"d-frequency", 130, 2, 257, ErrCorrupt}, {"literal-frequency", 258, 2, 1025, ErrCorrupt},
		} {
			t.Run(c.name, func(t *testing.T) {
				bad := bytes.Clone(corpus.LegacyV1)
				if c.width == 2 {
					binary.LittleEndian.PutUint16(bad[c.at:], uint16(c.value))
				} else {
					binary.LittleEndian.PutUint32(bad[c.at:], c.value)
				}
				if _, err := DecompressInto(make([]byte, 2), bad); !errors.Is(err, c.want) {
					t.Fatalf("corrupt legacy field: %v", err)
				}
			})
		}
	})

	counts := map[uint32]int{}
	verify := func(name string, algorithm uint32, plain, want []byte, capacity int) {
		t.Run(fmt.Sprintf("%x/%s/capacity%d", algorithm, name, capacity), func(t *testing.T) {
			dst := make([]byte, capacity)
			var n int
			if algorithm == 0x801 {
				n = EncodeBuffer(dst, plain)
			} else {
				n = EncodeLZVNBuffer(dst, plain)
			}
			if n != len(want) || !bytes.Equal(dst[:n], want) {
				t.Fatalf("native bytes differ: got %d native %d", n, len(want))
			}
		})
	}
	for _, c := range corpus.Cases {
		if c.Algorithm != 0x801 && c.Algorithm != 0x900 {
			continue
		}
		counts[c.Algorithm]++
		verify(c.Name, c.Algorithm, c.Plain, c.Encoded, 2097216)
	}
	for kind, want := range map[uint32]int{0x801: 366, 0x900: 366} {
		if counts[kind] != want {
			t.Fatalf("algorithm %x count=%d want=%d", kind, counts[kind], want)
		}
	}
	clear(counts)
	for _, b := range corpus.Bounded {
		if b.Input < 0 || b.Input >= len(corpus.Cases) {
			t.Fatal("invalid bounded input")
		}
		c := corpus.Cases[b.Input]
		if c.Algorithm != 0x801 && c.Algorithm != 0x900 {
			continue
		}
		counts[c.Algorithm]++
		verify(c.Name, c.Algorithm, c.Plain, b.Encoded, b.Capacity)
	}
	for kind, want := range map[uint32]int{0x801: 1228, 0x900: 1209} {
		if counts[kind] != want {
			t.Fatalf("bounded algorithm %x count=%d want=%d", kind, counts[kind], want)
		}
	}
}
