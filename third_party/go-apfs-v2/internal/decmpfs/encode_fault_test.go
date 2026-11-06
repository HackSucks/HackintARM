package decmpfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
)

type encodeReaderFunc func([]byte, int64) (int, error)

func (f encodeReaderFunc) ReadAt(p []byte, at int64) (int, error) { return f(p, at) }

type encodeWriterFunc func([]byte, int64) (int, error)

func (f encodeWriterFunc) WriteAt(p []byte, at int64) (int, error) { return f(p, at) }

func TestEncodeForkValidation(t *testing.T) {
	plain := bytes.NewReader([]byte("source"))
	target := make(encodeBuffer, 1024)
	for _, c := range []struct {
		name string
		src  io.ReaderAt
		dst  io.WriterAt
		size int64
		kind uint32
	}{
		{"source", nil, target, 6, 4}, {"destination", plain, nil, 6, 4}, {"zero", plain, target, 0, 4}, {"negative", plain, target, -1, 4},
		{"unknown", plain, target, 6, 6}, {"overflow-kind", plain, target, 6, math.MaxUint32},
		{"flat-index-overflow", plain, target, math.MaxInt64, 8}, {"zlib-index-overflow", plain, target, math.MaxInt64, 4},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := EncodeFork(t.Context(), c.src, c.size, c.kind, c.dst)
			if err == nil || got != (EncodedFork{}) {
				t.Fatalf("result=%+v err=%v", got, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := EncodeFork(ctx, plain, 6, 4, target); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := encodeBlock([]byte("x"), 99); err == nil {
		t.Fatal("unknown codec accepted")
	}
}

func TestEncodeForkIOFailures(t *testing.T) {
	failure := errors.New("injected storage failure")
	plain := bytes.Repeat([]byte("compressible block with transitions "), 4000)
	for _, kind := range []uint32{3, 7, 9, 11, 13} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			var writes int
			base := make(encodeBuffer, len(plain)+4096)
			record := encodeWriterFunc(func(p []byte, at int64) (int, error) { writes++; return base.WriteAt(p, at) })
			if _, err := EncodeFork(t.Context(), bytes.NewReader(plain), int64(len(plain)), kind, record); err != nil {
				t.Fatal(err)
			}
			for checkpoint := 1; checkpoint <= writes; checkpoint++ {
				for _, short := range []bool{false, true} {
					t.Run(fmt.Sprintf("write-%d-short-%v", checkpoint, short), func(t *testing.T) {
						calls := 0
						writer := encodeWriterFunc(func(p []byte, at int64) (int, error) {
							calls++
							if calls == checkpoint {
								if short {
									return len(p) - 1, failure
								}
								return 0, failure
							}
							return len(p), nil
						})
						got, err := EncodeFork(t.Context(), bytes.NewReader(plain), int64(len(plain)), kind, writer)
						if !errors.Is(err, failure) || !errors.Is(err, io.ErrShortWrite) || got != (EncodedFork{}) || calls != checkpoint {
							t.Fatalf("result=%+v calls=%d err=%v", got, calls, err)
						}
					})
				}
			}
			blocks := (len(plain) + BlockSize - 1) / BlockSize
			for checkpoint := 1; checkpoint <= blocks; checkpoint++ {
				for _, mode := range []string{"short", "full-error", "cancel-read", "cancel-write"} {
					t.Run(fmt.Sprintf("%s-%d", mode, checkpoint), func(t *testing.T) {
						ctx, cancel := context.WithCancel(t.Context())
						defer cancel()
						reads, writes := 0, 0
						reader := encodeReaderFunc(func(p []byte, at int64) (int, error) {
							reads++
							n, err := bytes.NewReader(plain).ReadAt(p, at)
							if reads == checkpoint {
								switch mode {
								case "short":
									return n - 1, io.EOF
								case "full-error":
									return n, failure
								case "cancel-read":
									cancel()
								}
							}
							return n, err
						})
						writer := encodeWriterFunc(func(p []byte, at int64) (int, error) {
							writes++
							if mode == "cancel-write" && reads == checkpoint {
								cancel()
							}
							return len(p), nil
						})
						got, err := EncodeFork(ctx, reader, int64(len(plain)), kind, writer)
						want := failure
						if mode == "short" {
							want = io.ErrUnexpectedEOF
						}
						if mode == "cancel-read" || mode == "cancel-write" {
							want = context.Canceled
						}
						if !errors.Is(err, want) || got != (EncodedFork{}) || reads != checkpoint {
							t.Fatalf("reads=%d writes=%d result=%+v err=%v", reads, writes, got, err)
						}
					})
				}
			}
		})
	}
}

func TestEncodeForkFullReadWithEOF(t *testing.T) {
	plain := bytes.Repeat([]byte("accepted full final read"), 20)
	reader := encodeReaderFunc(func(p []byte, at int64) (int, error) { n, _ := bytes.NewReader(plain).ReadAt(p, at); return n, io.EOF })
	a, b := make(encodeBuffer, 4096), make(encodeBuffer, 4096)
	got, err := EncodeFork(t.Context(), reader, int64(len(plain)), 4, a)
	if err != nil {
		t.Fatal(err)
	}
	want, err := EncodeFork(t.Context(), bytes.NewReader(plain), int64(len(plain)), 4, b)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || !bytes.Equal(a, b) {
		t.Fatal("full final read changed encoding")
	}
}

func TestEncodeForkNativeOffsetBounds(t *testing.T) {
	for _, c := range []struct {
		offset, length int64
		valid          bool
	}{
		{0, 0, true}, {math.MaxUint32 - 1, 1, true}, {math.MaxUint32, 0, true},
		{math.MaxUint32, 1, false}, {math.MaxUint32 + 1, 0, false},
		{0, math.MaxInt64, false}, {math.MaxInt64, math.MaxInt64, false},
		{-1, 1, false}, {1, -1, false},
	} {
		if err := checkEncodedExtent(c.offset, c.length); (err == nil) != c.valid {
			t.Fatalf("offset=%d length=%d err=%v", c.offset, c.length, err)
		}
	}
}
