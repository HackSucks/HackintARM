package accesstime

import (
	"errors"
	"os"
	"runtime"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
)

func TestRecordReadAccessInvalidFiles(t *testing.T) {
	if err := RecordReadAccess(nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil file: %v", err)
	}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := RecordReadAccess(dir); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("directory: %v", err)
	}
	file := heldfixture.Source(t, 0600)
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RecordReadAccess(file); err == nil || errors.Is(err, ErrReadAccessUnsupported) {
		t.Fatalf("closed file: %v", err)
	}
}

func TestRecordReadAccessUnsupportedHost(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Darwin supports mapped-read access recording")
	}
	file := heldfixture.Source(t, 0600)
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := RecordReadAccess(file); !errors.Is(err, ErrReadAccessUnsupported) {
		t.Fatalf("unsupported host: %v", err)
	}
	after, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unsupported recording changed the file")
	}
}
