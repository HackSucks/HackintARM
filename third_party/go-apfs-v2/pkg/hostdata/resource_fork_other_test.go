//go:build !darwin

package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCarrierNativeForkConstraint(t *testing.T) {
	f, e := os.Create(filepath.Join(t.TempDir(), "file"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = OpenResourceFork(f, true); !errors.Is(e, errors.ErrUnsupported) {
		t.Fatal(e)
	}
}
