package disk

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"runtime"
	"testing"
)

// mixedImage returns n bytes (a multiple of 512) that compress about the way a
// real file system does: runs of text, runs of incompressible bytes, and
// zero-filled stretches, interleaved at sub-chunk granularity.
func mixedImage(n int, seed int64) []byte {
	rng := rand.New(rand.NewSource(seed))
	out := make([]byte, 0, n)
	text := []byte("The quick brown fox jumps over the lazy dog. 0123456789\n")
	for len(out) < n {
		run := min(n-len(out), 4096+rng.Intn(60*1024))
		switch rng.Intn(3) {
		case 0:
			for i := range run {
				out = append(out, text[(i+rng.Intn(4))%len(text)])
			}
		case 1:
			buf := make([]byte, run)
			rng.Read(buf)
			out = append(out, buf...)
		default:
			out = append(out, make([]byte, run)...)
		}
	}
	return out[:n/512*512]
}

var benchCodecs = []struct {
	name string
	c    Compression
}{
	{"zlib", CompressionZlib},
	{"lzfse", CompressionLZFSE},
	{"lzma", CompressionLZMA},
}

// BenchmarkEncodeUDIF measures DMG encoding throughput per codec, with one
// worker and with one per CPU.
func BenchmarkEncodeUDIF(b *testing.B) {
	img := mixedImage(64<<20, 1)
	for _, tc := range benchCodecs {
		for _, workers := range []int{1, runtime.GOMAXPROCS(0)} {
			b.Run(fmt.Sprintf("%s/workers=%d", tc.name, workers), func(b *testing.B) {
				blocks := []SourceBlock{{Name: "disk image", Data: img}}
				b.SetBytes(int64(len(img)))
				for b.Loop() {
					opts := &EncodeOptions{Compression: tc.c, Workers: workers}
					if err := EncodeUDIF(io.Discard, blocks, opts); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// TestEncodeUDIFDeterministicPerCodec encodes the same input twice with each
// codec and requires byte-identical output. Reproducible DMGs depend on it,
// and any change to how chunks are scheduled must keep it true.
func TestEncodeUDIFDeterministicPerCodec(t *testing.T) {
	img := mixedImage(8<<20, 2)
	blocks := []SourceBlock{{Name: "disk image", Data: img}}
	for _, tc := range append(benchCodecs, struct {
		name string
		c    Compression
	}{"none", CompressionNone}) {
		t.Run(tc.name, func(t *testing.T) {
			var sums [2][32]byte
			for i := range sums {
				var buf bytes.Buffer
				if err := EncodeUDIF(&buf, blocks, &EncodeOptions{Compression: tc.c}); err != nil {
					t.Fatalf("EncodeUDIF: %v", err)
				}
				sums[i] = sha256.Sum256(buf.Bytes())
			}
			if sums[0] != sums[1] {
				t.Fatalf("two encodes differ: %x != %x", sums[0][:8], sums[1][:8])
			}
			t.Logf("sha256 %x", sums[0][:8])
		})
	}
}
