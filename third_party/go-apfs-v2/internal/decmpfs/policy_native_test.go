package decmpfs

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
)

func TestEncodeNativeContentPolicy(t *testing.T) {
	f, err := os.Open("../../testdata/appledouble/native/compression-policy.json.gz")
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
		Schema int
		Cases  []struct {
			Filesystem, Requested, Inline, Pattern, Family string
			Size, RandomTail, MeasuredPayload              int
			Attribute, Fork                                []byte
			LogicalSHA256                                  string
			After                                          struct {
				Flags    uint32
				Size     int64
				Accepted bool
			}
		}
	}
	if err := json.NewDecoder(z).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != 1 || len(corpus.Cases) != 4632 {
		t.Fatal("incomplete policy inventory")
	}
	for _, c := range corpus.Cases {
		t.Run(fmt.Sprintf("%s/%s/%s/%s/%s/%d/%d", c.Filesystem, c.Requested, c.Inline, c.Family, c.Pattern, c.Size, c.RandomTail), func(t *testing.T) {
			plain := policyInput(c.Size, c.Pattern, c.RandomTail)
			if fmt.Sprintf("%x", sha256.Sum256(plain)) != c.LogicalSHA256 {
				t.Fatal("native input digest differs")
			}
			if !c.After.Accepted || c.After.Size != int64(c.Size) || (c.After.Flags&32 != 0) != (len(c.Attribute) != 0) {
				t.Fatal("inconsistent native outcome")
			}
			kind := 0
			if c.Requested != "default" {
				kind, err = strconv.Atoi(c.Requested)
				if err != nil {
					t.Fatal(err)
				}
			}
			target := make(encodeBuffer, len(plain)+4096)
			got, err := Encode(t.Context(), bytes.NewReader(plain), int64(len(plain)), target, EncodeOptions{Type: uint32(kind), ResourceForkOnly: c.Inline == "no"})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Attribute, c.Attribute) || got.ForkSize != int64(len(c.Fork)) || !bytes.Equal(target[:got.ForkSize], c.Fork) {
				t.Fatalf("native policy/storage differs: attribute %x/%x fork extent %d/%d", got.Attribute, c.Attribute, got.ForkSize, len(c.Fork))
			}
			if c.Family != "grid" {
				measured := 0
				for at := 0; at < len(plain); at += BlockSize {
					block, err := encodeBlock(plain[at:min(at+BlockSize, len(plain))], uint32(kind+1))
					if err != nil {
						t.Fatal(err)
					}
					measured += len(block)
				}
				if measured != c.MeasuredPayload {
					t.Fatalf("native payload measurement %d, Go %d", c.MeasuredPayload, measured)
				}
			}
			if len(got.Attribute) == 0 {
				return
			}
			data := got.Attribute
			if got.ForkSize != 0 {
				data = target[:got.ForkSize]
			}
			method, err := MethodFor(binary.LittleEndian.Uint32(got.Attribute[4:8]))
			if err != nil {
				t.Fatal(err)
			}
			h, err := NewHandle(&memSource{data: data}, uint64(len(plain)), method)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			decoded := make([]byte, len(plain))
			for at := 0; at < len(decoded); {
				p := decoded[at:min(at+4331, len(decoded))]
				n, err := h.ReadSegmentData(0, p)
				if err != nil || n != len(p) {
					t.Fatalf("decode at %d: %d %v", at, n, err)
				}
				at += n
			}
			if !bytes.Equal(decoded, plain) {
				t.Fatal("encoded logical content changed")
			}
		})
	}
}

func policyInput(size int, pattern string, tail int) []byte {
	switch pattern {
	case "text":
		tail = 0
	case "random":
		tail = size
	case "half-random":
		tail = size - size/2
	case "mostly-random":
		tail = size - size/10
	}
	plain := make([]byte, size)
	var random uint32 = 0x12345678
	for i := range plain {
		random ^= random << 13
		random ^= random >> 17
		random ^= random << 5
		plain[i] = "ABCD"[i%4]
		if i >= size-tail {
			plain[i] = byte(random)
		}
	}
	return plain
}
