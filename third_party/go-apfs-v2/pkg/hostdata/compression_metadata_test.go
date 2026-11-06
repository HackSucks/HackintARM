package hostdata

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

func compressionMetadataHeader(kind uint32) []byte {
	b := make([]byte, 24)
	copy(b, "fpmc")
	binary.LittleEndian.PutUint32(b[4:], kind)
	binary.LittleEndian.PutUint64(b[8:], 65536)
	copy(b[16:], "abcdefgh")
	return b
}
func TestCaptureCompressionMetadataBounded(t *testing.T) {
	for _, kind := range []uint32{0, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 99} {
		header := compressionMetadataHeader(kind)
		calls := 0
		reads := 0
		metadata, err := captureCompressionMetadata(t.Context(), 24, func() (uint32, uint64, error) { calls++; return UFCompressed, 65536, nil }, func(name string, p []byte) (int, error) {
			if name == ResourceForkName {
				reads++
				if p != nil {
					t.Fatal("read resource-fork payload")
				}
				return 1<<33 + 17, nil
			}
			if name != DecmpfsName {
				t.Fatal("unrelated metadata requested", name)
			}
			if p == nil {
				return len(header), nil
			}
			if len(p) != 24 {
				t.Fatal("unexpected allocation", len(p))
			}
			return copy(p, header), nil
		})
		if err != nil || calls != 2 {
			t.Fatal(kind, calls, err)
		}
		wantsFork := kind == 4 || kind == 8 || kind == 10 || kind == 12 || kind == 14 || kind == 16
		if (reads == 1) != wantsFork {
			t.Fatal("incorrect fork query", kind, reads)
		}
		got, e := decmpfs.Query(t.Context(), metadata)
		if e != nil || got.Type != kind || got.LogicalSize != 65536 {
			t.Fatal(kind, got, e)
		}
		if wantsFork && got.StoredSize != 1<<33+41 {
			t.Fatal("fork extent narrowed", got)
		}
		clear(header)
		retained := make([]byte, 4)
		if _, e = metadata.Attribute.ReadAt(retained, 0); e != nil || string(retained) != "fpmc" {
			t.Fatal("snapshot borrowed mutable source", e)
		}
	}
}
func TestCaptureCompressionMetadataFailures(t *testing.T) {
	sentinel := errors.New("metadata failure")
	cases := []struct {
		name                      string
		limit                     int
		stateFailure, changedStat int
		getFailure                string
		cancelAt                  string
		want                      error
	}{
		{name: "initial stat", limit: 24, stateFailure: 1, want: sentinel},
		{name: "final stat", limit: 24, stateFailure: 2, want: sentinel},
		{name: "changed flags", limit: 24, changedStat: 1, want: ErrXattrChanged},
		{name: "changed size", limit: 24, changedStat: 2, want: ErrXattrChanged},
		{name: "attribute size", limit: 24, getFailure: "size", want: sentinel},
		{name: "attribute read", limit: 24, getFailure: "read", want: sentinel},
		{name: "fork size", limit: 24, getFailure: "fork", want: sentinel},
		{name: "allocation budget", limit: 23, want: ErrXattrTooLarge},
		{name: "attribute cancellation", limit: 24, cancelAt: "read", want: context.Canceled},
		{name: "initial cancellation", limit: 24, cancelAt: "before", want: context.Canceled},
		{name: "final cancellation", limit: 24, cancelAt: "final", want: context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancelAt == "before" {
				cancel()
			}
			calls := 0
			metadata, e := captureCompressionMetadata(ctx, tc.limit, func() (uint32, uint64, error) {
				calls++
				if calls == tc.stateFailure {
					return 0, 0, sentinel
				}
				if calls == 2 {
					if tc.cancelAt == "final" {
						cancel()
					}
					if tc.changedStat == 1 {
						return 0, 65536, nil
					}
					if tc.changedStat == 2 {
						return UFCompressed, 65537, nil
					}
				}
				return UFCompressed, 65536, nil
			}, func(name string, p []byte) (int, error) {
				stage := "size"
				if p != nil {
					stage = "read"
				}
				if name == ResourceForkName {
					stage = "fork"
				}
				if stage == tc.getFailure {
					return 0, sentinel
				}
				if stage == tc.cancelAt {
					cancel()
				}
				if name == ResourceForkName {
					return 1024, nil
				}
				if p == nil {
					return 24, nil
				}
				return copy(p, compressionMetadataHeader(8)), nil
			})
			if !errors.Is(e, tc.want) || metadata.Attribute != nil || metadata.Flags != 0 {
				t.Fatal(metadata, e, tc.want)
			}
		})
	}
}
func TestCaptureCompressionMetadataAbsent(t *testing.T) {
	for _, attribute := range [][]byte{nil, {}, []byte("bad"), append([]byte("nope"), make([]byte, 20)...), compressionMetadataHeader(8)} {
		metadata, e := captureCompressionMetadata(t.Context(), 24, func() (uint32, uint64, error) { return UFCompressed, 0, nil }, func(name string, p []byte) (int, error) {
			if name == ResourceForkName || attribute == nil {
				return 0, missingXattrError
			}
			if p == nil {
				return len(attribute), nil
			}
			return copy(p, attribute), nil
		})
		if e != nil || metadata.ResourceForkSize != -1 {
			t.Fatal(metadata, e)
		}
		if attribute == nil && metadata.Attribute != nil {
			t.Fatal("missing attribute became present")
		}
	}
	metadata, e := captureCompressionMetadata(t.Context(), 0, func() (uint32, uint64, error) { return 0, 1 << 33, nil }, func(string, []byte) (int, error) {
		t.Fatal("queried attributes of uncompressed file")
		return 0, io.ErrUnexpectedEOF
	})
	if e != nil || metadata.LogicalSize != 1<<33 || metadata.Attribute != nil {
		t.Fatal(metadata, e)
	}
}
func TestCompressionMetadataInvalidArguments(t *testing.T) {
	if _, e := QueryCompression(t.Context(), nil, -1); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	if _, e := QueryCompression(t.Context(), nil, 0); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	if _, e := CompressionVolumeFlags(t.Context(), nil); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := CompressionVolumeFlags(ctx, nil); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
