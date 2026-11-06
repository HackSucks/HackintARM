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

func TestEncodePolicyValidationAndSizeBoundaries(t *testing.T) {
	plain := bytes.Repeat([]byte("abcd"), 8192)
	source := bytes.NewReader(plain)
	target := make(encodeBuffer, len(plain)+4096)
	for _, c := range []struct {
		source io.ReaderAt
		target io.WriterAt
		size   int64
		kind   uint32
	}{
		{nil, target, 32768, 0}, {source, nil, 32768, 0}, {source, target, -1, 0},
		{source, target, 32768, 5}, {source, target, 32768, 6}, {source, target, 32768, math.MaxUint32},
	} {
		got, err := Encode(t.Context(), c.source, c.size, c.target, EncodeOptions{Type: c.kind})
		if err == nil || got.Attribute != nil || got.ForkSize != 0 {
			t.Fatalf("%+v: %+v %v", c, got, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Encode(ctx, source, 32768, target, EncodeOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	noRead := encodeReaderFunc(func([]byte, int64) (int, error) { t.Fatal("ineligible input read"); return 0, nil })
	noWrite := encodeWriterFunc(func([]byte, int64) (int, error) { t.Fatal("ineligible output written"); return 0, nil })
	for _, size := range []int64{0, 1, 16383, 16384, 512<<20 + 1, math.MaxInt64} {
		got, err := Encode(t.Context(), noRead, size, noWrite, EncodeOptions{})
		if err != nil || got.Attribute != nil || got.ForkSize != 0 {
			t.Fatalf("size=%d: %+v %v", size, got, err)
		}
	}
	failure := errors.New("first eligible read")
	for _, size := range []int64{16385, 512<<20 - 1, 512 << 20} {
		reads := 0
		reader := encodeReaderFunc(func(p []byte, at int64) (int, error) {
			reads++
			if at != 0 || len(p) > 65536 {
				t.Fatal("unbounded first read")
			}
			return 0, failure
		})
		got, err := Encode(t.Context(), reader, size, noWrite, EncodeOptions{})
		if !errors.Is(err, failure) || reads != 1 || got.Attribute != nil {
			t.Fatalf("size=%d: %+v %v reads=%d", size, got, err, reads)
		}
	}
}

func TestEncodePolicyInlineAndDeclineOwnership(t *testing.T) {
	for _, kind := range []uint32{0, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			plain := policyInput(65536, "text", 0)
			writes := 0
			target := make(encodeBuffer, len(plain)+4096)
			writer := encodeWriterFunc(func(p []byte, at int64) (int, error) { writes++; return target.WriteAt(p, at) })
			got, err := Encode(t.Context(), bytes.NewReader(plain), int64(len(plain)), writer, EncodeOptions{Type: kind})
			if err != nil || len(got.Attribute) == 0 {
				t.Fatalf("%+v %v", got, err)
			}
			if kind != 9 && kind != 10 && (got.ForkSize != 0 || writes != 0) {
				t.Fatal("inline output wrote to caller storage")
			}
			if kind == 9 || kind == 10 {
				return
			}
			// Incompressible second block declines after first-block output. The
			// caller must not mistake those staged bytes for completed storage.
			plain = policyInput(131072, "random", 0)
			writes = 0
			got, err = Encode(t.Context(), bytes.NewReader(plain), int64(len(plain)), writer, EncodeOptions{Type: kind})
			if err != nil || got.Attribute != nil || got.ForkSize != 0 || writes == 0 {
				t.Fatalf("partial decline: %+v %v writes=%d", got, err, writes)
			}
		})
	}
}

func TestEncodePolicyIOAndCancellation(t *testing.T) {
	failure := errors.New("injected failure")
	plain := policyInput(131072, "text", 0)
	for _, mode := range []string{"write", "short", "read", "cancel-read", "cancel-write"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reader := encodeReaderFunc(func(p []byte, at int64) (int, error) {
				n, err := bytes.NewReader(plain).ReadAt(p, at)
				if mode == "read" {
					return n, failure
				}
				if mode == "cancel-read" {
					cancel()
				}
				return n, err
			})
			writer := encodeWriterFunc(func(p []byte, at int64) (int, error) {
				if mode == "write" {
					return 0, failure
				}
				if mode == "short" {
					return len(p) - 1, nil
				}
				if mode == "cancel-write" {
					cancel()
				}
				return len(p), nil
			})
			got, err := Encode(ctx, reader, int64(len(plain)), writer, EncodeOptions{})
			want := failure
			if mode == "short" {
				want = io.ErrShortWrite
			}
			if mode == "cancel-read" || mode == "cancel-write" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || got.Attribute != nil || got.ForkSize != 0 {
				t.Fatalf("%+v %v", got, err)
			}
		})
	}
}
