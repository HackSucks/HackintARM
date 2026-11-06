package heldfixture

import (
	"os"
	"path/filepath"
	"testing"
)

func Source(t *testing.T, mode os.FileMode) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "original")
	if err := os.WriteFile(path, []byte("original contents longer than the replacement"), mode); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close(); _ = os.Chmod(path, 0600) })
	return f
}
