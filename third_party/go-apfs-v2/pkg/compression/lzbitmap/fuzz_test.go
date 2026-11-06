package lzbitmap

import (
	"bytes"
	"os"
	"testing"
)

// FuzzLZBitmapDecompress feeds malformed streams to the decoder. A payload comes
// from a package the tool did not build, so every bound in the format is
// attacker-controlled: chunk lengths, the three metadata offsets, the
// repetition counts and the periods that index backwards into the output.
// The decoder must reject bad input rather than panic or run away with
// memory.
func FuzzLZBitmapDecompress(f *testing.F) {
	f.Add([]byte(Magic))
	f.Add(append([]byte(Magic), 0x06, 0, 0, 0, 0, 0)) // empty terminating chunk
	if b, err := os.ReadFile(appleCompressed); err == nil && len(b) > 12 {
		// A real chunk from Apple's own output, minus the container.
		f.Add(b[28:])
	}
	for _, in := range [][]byte{
		bytes.Repeat([]byte("the quick brown fox "), 40),
		bytes.Repeat([]byte{0}, 5000),
		[]byte("hello"),
	} {
		if enc, err := Compress(in); err == nil {
			f.Add(enc)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := DecompressLimit(data, 1<<20)
		if err != nil {
			return
		}
		// Anything that decodes must re-encode and decode back to itself.
		enc, err := Compress(out)
		if err != nil {
			t.Fatalf("cannot re-encode %d bytes: %v", len(out), err)
		}
		back, err := Decompress(enc)
		if err != nil {
			t.Fatalf("cannot decode our own encoding: %v", err)
		}
		for _, capacity := range []int{len(out), len(enc) + 31, len(enc) + 128} {
			dst := make([]byte, capacity)
			if n := EncodeBuffer(dst, out); n != 0 {
				decoded, err := DecompressLimit(dst[:n], len(out))
				if err != nil || !bytes.Equal(decoded, out) {
					t.Fatalf("bounded re-encode changed bytes: %v", err)
				}
			}
		}
		if !bytes.Equal(back, out) {
			t.Fatal("re-encoding changed the bytes")
		}
	})
}
