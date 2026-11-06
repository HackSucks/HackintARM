package hostdata

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

func TestCommitHeldCompressionBinding(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "binding-")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	storage := decmpfs.EncodedFile{Attribute: compressionMetadataHeader(8)[:16], ForkSize: 12}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e = CommitHeldCompression(ctx, f, storage, StatCopySource{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = CommitHeldCompression(t.Context(), nil, storage, StatCopySource{}); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	sentinel := errors.New("held binding failed")
	if _, e = commitHeldCompressionUsing(t.Context(), f, storage, StatCopySource{}, func(got *os.File) (CompressionCommitBackend, error) {
		if got != f {
			t.Fatal("redirected descriptor")
		}
		return nil, sentinel
	}); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	var truncated, flagged, synchronized, timed bool
	b := compressionCommitFunctions{
		compressionFlagFunctions: compressionFlagFunctions{read: func() (uint32, error) { return 0, nil }, compare: func(a, b uint32) (uint32, error) { flagged = true; return a, nil }},
		attribute:                func([]byte) error { return nil }, mode: func(uint16) error { t.Fatal("unexpected mode change"); return nil },
		truncate: func(size int64) error {
			if size != 0 {
				t.Fatal(size)
			}
			truncated = true
			return nil
		},
		sync: func() error { synchronized = true; return nil }, times: func(time.Time, time.Time) error { timed = true; return nil },
	}
	r, e := commitHeldCompressionUsing(t.Context(), f, storage, StatCopySource{}, func(got *os.File) (CompressionCommitBackend, error) {
		if got != f {
			t.Fatal("redirected descriptor")
		}
		return b, nil
	})
	if e != nil || !r.Completed || !truncated || !flagged || !synchronized || !timed {
		t.Fatal(r, e)
	}
	if _, e = f.Stat(); e != nil {
		t.Fatal("closed caller handle", e)
	}
}
