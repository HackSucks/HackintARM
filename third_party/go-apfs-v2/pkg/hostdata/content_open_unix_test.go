//go:build darwin || linux

package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestContentOpenNonblockingFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(dir, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := OpenContentFileRead(root, "fifo"); !errors.Is(err, ErrContentType) {
		t.Fatal("FIFO accepted", err)
	}
}
