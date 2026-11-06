package lzbitmap

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	cases := map[string][]byte{
		"empty":       {},
		"one byte":    {0x41},
		"short":       []byte("hello"),
		"eight":       []byte("abcdefgh"),
		"repetitive":  bytes.Repeat([]byte("the quick brown fox "), 500),
		"zeros":       make([]byte, 40000),
		"two chunks":  bytes.Repeat([]byte("abcdefgh"), MaxChunk/4),
		"exact chunk": bytes.Repeat([]byte{7}, MaxChunk),
	}
	r := rand.New(rand.NewSource(1))
	random := make([]byte, 70000)
	r.Read(random)
	cases["random"] = random
	mixed := append(append([]byte{}, random[:1000]...), bytes.Repeat([]byte("xyz"), 9000)...)
	cases["mixed"] = mixed

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			enc, err := Compress(in)
			if err != nil {
				t.Fatalf("compress: %v", err)
			}
			out, err := Decompress(enc)
			if err != nil {
				t.Fatalf("decompress: %v", err)
			}
			if !bytes.Equal(out, in) {
				t.Fatalf("round trip differs: got %d bytes, want %d", len(out), len(in))
			}
			t.Logf("%d -> %d bytes", len(in), len(enc))
		})
	}
}
