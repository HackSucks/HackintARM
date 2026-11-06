package disk

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
)

// parallelTestBlocks returns blocks exercising every chunk kind: compressible,
// incompressible (stored raw), all-zero, a lazily read block, an absent one
// and a final partial chunk.
func parallelTestBlocks() []SourceBlock {
	img := mixedImage(3<<20, 9)
	copy(img[1<<20:], make([]byte, 256<<10)) // a zero-fill run
	lazy := mixedImage(2<<20+512*3, 10)
	return []SourceBlock{
		{Name: "data", StartSector: 0, Data: img},
		{Name: "lazy", StartSector: uint64(len(img)) / 512, SectorCount: uint64(len(lazy)) / 512, Reader: bytes.NewReader(lazy)},
		{Name: "zeros", StartSector: uint64(len(img)+len(lazy)) / 512, SectorCount: 4096},
	}
}

// TestParallelEncodeMatchesSequential requires the same bytes from every
// worker count, with every codec and chunk size.
func TestParallelEncodeMatchesSequential(t *testing.T) {
	for _, c := range []Compression{CompressionZlib, CompressionLZFSE, CompressionLZMA, CompressionNone} {
		for _, chunk := range []uint64{0, 64} {
			var want [32]byte
			for i, workers := range []int{1, 2, 3, 8, 0} {
				var buf bytes.Buffer
				opts := &EncodeOptions{Compression: c, ChunkSectors: chunk, Workers: workers}
				if err := EncodeUDIF(&buf, parallelTestBlocks(), opts); err != nil {
					t.Fatalf("codec %d, %d workers: %v", c, workers, err)
				}
				got := sha256.Sum256(buf.Bytes())
				if i == 0 {
					want = got
					continue
				}
				if got != want {
					t.Fatalf("codec %d, chunk %d sectors: %d workers wrote %x, one worker %x", c, chunk, workers, got[:8], want[:8])
				}
			}
		}
	}
}

// failingReader fails once a read reaches offset at.
type failingReader struct {
	r  io.ReaderAt
	at int64
}

var errInjected = errors.New("injected read failure")

func (f failingReader) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > f.at {
		return 0, errInjected
	}
	return f.r.ReadAt(p, off)
}

// failingWriter fails once n bytes have been written.
type failingWriter struct{ n int }

func (w *failingWriter) Write(p []byte) (int, error) {
	if len(p) > w.n {
		return 0, errInjected
	}
	w.n -= len(p)
	return len(p), nil
}

// TestParallelEncodeReportsErrors checks a failing reader or writer stops the
// encode with its error, rather than hanging the pipeline.
func TestParallelEncodeReportsErrors(t *testing.T) {
	src := mixedImage(8<<20, 11)
	for _, workers := range []int{1, 4} {
		opts := &EncodeOptions{Compression: CompressionLZFSE, ChunkSectors: 64, Workers: workers}

		blocks := []SourceBlock{{Name: "r", SectorCount: uint64(len(src)) / 512,
			Reader: failingReader{bytes.NewReader(src), 5 << 20}}}
		if err := EncodeUDIF(io.Discard, blocks, opts); !errors.Is(err, errInjected) {
			t.Fatalf("%d workers, failing reader: err = %v", workers, err)
		}

		blocks = []SourceBlock{{Name: "w", Data: src}}
		if err := EncodeUDIF(&failingWriter{n: 1 << 20}, blocks, opts); !errors.Is(err, errInjected) {
			t.Fatalf("%d workers, failing writer: err = %v", workers, err)
		}
	}
}
