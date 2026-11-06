//go:build !darwin

package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCompressionPathForeignNativeView(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := QueryCompressionNoFollow(t.Context(), path, info, 24); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := nativeCompressionPathXattr(path, DecmpfsName, nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
}
