package lzbitmap

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

// Preserve decoding compatibility with the previous scalar encoder. Its exact
// outputs predate native encoder qualification; their hashes remain unchanged.
// Native output is pinned independently in TestEncodeNativeBufferCorpus.
func TestDecodeScalarOutputVectors(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	random := make([]byte, 3*MaxChunk+7)
	for i := range random {
		random[i] = byte(r.Uint32())
	}
	cases := []struct {
		name string
		data []byte
		size int
		hash string
	}{
		{"random", random, 98345, "4513049dec85eeff9bb6da6b707146a94bd34e4d25d894c1bbdc2426d4490183"},
		{"random-to-repeated", append(bytes.Clone(random[:MaxChunk]), bytes.Repeat([]byte("abcdefgh12345678"), 4096)...), 33143, "4e1322a95fb7140423570305870d498015ffad90ca994a552595d72886b36ef4"},
		{"repeated-to-random", append(bytes.Repeat([]byte("abcdefg"), 5000), random[:MaxChunk]...), 33221, "cd8d0acb471dbb90d5fd90b3690581734123fa25dbbc09a36b40eccc9b2861e2"},
		{"history", append(bytes.Clone(random[:65535]), random[1024:32768]...), 65726, "3134ae82bc567ca2dcc639b304f94688aadecb56548099be747c6152d4e36735"},
		{"tail", bytes.Repeat([]byte("abcd"), 8193), 198, "38f58b502cdd70cef40a9df436fc423ea581dfb711af360f5b80183ef96633bb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := os.ReadFile(filepath.Join("testdata", "scalar", tc.name+".zbm"))
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) != tc.size || fmt.Sprintf("%x", sha256.Sum256(encoded)) != tc.hash {
				t.Fatal("retained scalar fixture changed")
			}
			decoded, err := Decompress(encoded)
			if err != nil || !bytes.Equal(decoded, tc.data) {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
}
