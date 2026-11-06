package hostdata

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestFilesystemMetadataStorageLifetime(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "storage")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := FilesystemUsesXattrFiles(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("borrowed")); err != nil {
		t.Fatal("query closed caller handle", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if value, err := FilesystemUsesXattrFiles(t.Context(), f); value || err == nil {
		t.Fatal(value, err)
	}
	if value, err := FilesystemUsesXattrFiles(t.Context(), nil); value || err == nil {
		t.Fatal(value, err)
	}
}

func TestFilesystemMetadataStorageCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	calls := 0
	query := func(*os.File) (bool, error) { calls++; return true, nil }
	if v, err := filesystemXattrStorageUsing(ctx, nil, query); v || !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal(v, err, calls)
	}
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	sentinel := errors.New("volume query failure")
	v, err := filesystemXattrStorageUsing(ctx, nil, func(*os.File) (bool, error) { cancel(); return true, sentinel })
	if v || !errors.Is(err, sentinel) || !errors.Is(err, context.Canceled) {
		t.Fatal(v, err)
	}
	for _, want := range []bool{false, true} {
		v, err := filesystemXattrStorageUsing(t.Context(), nil, func(*os.File) (bool, error) { return want, nil })
		if err != nil || v != want {
			t.Fatal(v, err)
		}
	}
}
