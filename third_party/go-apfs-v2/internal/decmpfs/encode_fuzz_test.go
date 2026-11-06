package decmpfs

import (
	"bytes"
	"io"
	"testing"
)

func FuzzEncodeFork(f *testing.F) {
	for _, n := range []int{1, 7, 8, 63, 64, 144, 145, 257, BlockSize - 1, BlockSize, BlockSize + 1, 2*BlockSize + 123} {
		for kind := uint8(0); kind < 5; kind++ {
			f.Add(bytes.Repeat([]byte("abcdefgh"), n/8+1)[:n], kind)
		}
	}
	f.Fuzz(func(t *testing.T, plain []byte, selector uint8) {
		if len(plain) == 0 || len(plain) > 3*BlockSize+123 {
			return
		}
		kind := [...]uint32{4, 8, 10, 12, 14}[selector%5]
		target := make(encodeBuffer, len(plain)+4096)
		result, err := EncodeFork(t.Context(), bytes.NewReader(plain), int64(len(plain)), kind, target)
		if err != nil {
			t.Fatal(err)
		}
		method, err := MethodFor(kind)
		if err != nil {
			t.Fatal(err)
		}
		h, err := NewHandle(&memSource{data: target[:result.Size]}, uint64(len(plain)), method)
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		decoded := make([]byte, len(plain))
		for at := 0; at < len(decoded); {
			p := decoded[at:min(len(decoded), at+4331)]
			n, err := h.ReadSegmentData(0, p)
			if err != nil || n != len(p) {
				t.Fatalf("decode progress at %d: n=%d err=%v", at, n, err)
			}
			at += n
		}
		if !bytes.Equal(decoded, plain) {
			t.Fatal("compression fork changed logical bytes")
		}
		var tail [1]byte
		if n, err := h.ReadSegmentData(0, tail[:]); n != 0 || err != io.EOF {
			t.Fatalf("logical end: %d %v", n, err)
		}
	})
}
