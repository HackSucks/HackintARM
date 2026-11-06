package decmpfs

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzEncodePolicy(f *testing.F) {
	for _, n := range []int{0, 16384, 16385, BlockSize - 1, BlockSize, BlockSize + 1, 2*BlockSize + 123} {
		for kind := uint8(0); kind < 6; kind++ {
			f.Add(policyInput(n, "text", 0), kind, false)
			f.Add(policyInput(n, "half-random", 0), kind, true)
		}
	}
	f.Fuzz(func(t *testing.T, plain []byte, selector uint8, forkOnly bool) {
		if len(plain) > 3*BlockSize+123 {
			return
		}
		kind := [...]uint32{0, 3, 7, 9, 11, 13}[selector%6]
		target := make(encodeBuffer, len(plain)+4096)
		result, err := Encode(t.Context(), bytes.NewReader(plain), int64(len(plain)), target, EncodeOptions{Type: kind, ResourceForkOnly: forkOnly})
		if err != nil {
			t.Fatal(err)
		}
		if result.Attribute == nil {
			if result.ForkSize != 0 {
				t.Fatal("declined output exposed a fork")
			}
			return
		}
		method, err := MethodFor(binary.LittleEndian.Uint32(result.Attribute[4:8]))
		if err != nil {
			t.Fatal(err)
		}
		data := result.Attribute
		if result.ForkSize != 0 {
			data = target[:result.ForkSize]
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
			t.Fatal("policy changed logical bytes")
		}
	})
}
