package hostdata

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCompressionPathObservation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	header := compressionMetadataHeader(3)
	flags := func(os.FileInfo) (uint32, bool) { return UFCompressed, true }
	get := func(_, name string, b []byte) (int, error) {
		if name != DecmpfsName {
			t.Fatal(name)
		}
		if b != nil {
			copy(b, header)
		}
		return len(header), nil
	}
	query := func(ctx context.Context, info os.FileInfo, limit int, stat func(string) (os.FileInfo, error), flag func(os.FileInfo) (uint32, bool), read func(string, string, []byte) (int, error)) error {
		_, err := queryCompressionPathUsing(ctx, path, info, limit, stat, flag, read)
		return err
	}
	t.Run("valid", func(t *testing.T) {
		got, err := queryCompressionPathUsing(t.Context(), path, expected, len(header), os.Lstat, flags, get)
		if err != nil || got.Type != 3 || got.StoredSize != uint64(len(header)) {
			t.Fatal(got, err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		directory, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, info := range []os.FileInfo{nil, directory} {
			if err := query(t.Context(), info, 24, os.Lstat, flags, get); !errors.Is(err, os.ErrInvalid) {
				t.Fatal(err)
			}
		}
		if err := query(t.Context(), expected, -1, os.Lstat, flags, get); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
	})
	t.Run("cancel-before", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := query(ctx, expected, 24, os.Lstat, flags, get); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("stat-error", func(t *testing.T) {
		sentinel := errors.New("stat")
		err := query(t.Context(), expected, 24, func(string) (os.FileInfo, error) { return nil, sentinel }, flags, get)
		if !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
	})
	t.Run("invalid-native-size", func(t *testing.T) {
		err := query(t.Context(), expected, 24, func(string) (os.FileInfo, error) { return compressionPathNegativeSize{expected}, nil }, flags, get)
		if !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
	})
	t.Run("unknown-native-flags", func(t *testing.T) {
		err := query(t.Context(), expected, 24, os.Lstat, func(os.FileInfo) (uint32, bool) { return 0, false }, get)
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Fatal(err)
		}
	})
	t.Run("xattr-error", func(t *testing.T) {
		sentinel := errors.New("xattr")
		err := query(t.Context(), expected, 24, os.Lstat, flags, func(string, string, []byte) (int, error) { return 0, sentinel })
		if !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
	})
	t.Run("bounded-attribute", func(t *testing.T) {
		if err := query(t.Context(), expected, len(header)-1, os.Lstat, flags, get); !errors.Is(err, ErrXattrTooLarge) {
			t.Fatal(err)
		}
	})
	t.Run("cancel-after-read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		err := query(ctx, expected, 24, os.Lstat, flags, func(p, n string, b []byte) (int, error) {
			if b != nil {
				cancel()
			}
			return get(p, n, b)
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("replacement-during-read", func(t *testing.T) {
		other := filepath.Join(dir, "other")
		if err := os.WriteFile(other, []byte("different"), 0600); err != nil {
			t.Fatal(err)
		}
		otherInfo, err := os.Lstat(other)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		err = query(t.Context(), expected, 24, func(string) (os.FileInfo, error) {
			calls++
			if calls == 1 {
				return expected, nil
			}
			return otherInfo, nil
		}, flags, get)
		if !errors.Is(err, ErrMetadataIdentity) {
			t.Fatal(err)
		}
	})
	t.Run("nonregular-replacement", func(t *testing.T) {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		err = query(t.Context(), expected, 24, func(string) (os.FileInfo, error) { return info, nil }, flags, get)
		if !errors.Is(err, ErrMetadataIdentity) {
			t.Fatal(err)
		}
	})
}

type compressionPathNegativeSize struct{ os.FileInfo }

func (compressionPathNegativeSize) Size() int64 { return -1 }
