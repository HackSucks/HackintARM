package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
)

func TestSetCreationTimeInvalidFiles(t *testing.T) {
	when := time.Unix(946684800, 123456789)
	if err := SetCreationTime(nil, when); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil file: %v", err)
	}
	r, pipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer pipe.Close()
	if err := SetCreationTime(pipe, when); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("pipe: %v", err)
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "closed"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := SetCreationTime(file, when); err == nil || errors.Is(err, ErrCreationTimeUnsupported) {
		t.Fatalf("closed file: %v", err)
	}
}

func TestSetCreationTimeUnsupportedHost(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		t.Skip("host supports creation-time updates; covered by native tests")
	}
	file := heldfixture.Source(t, 0640)
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCreationTime(file, time.Unix(946684800, 123456789)); !errors.Is(err, ErrCreationTimeUnsupported) {
		t.Fatalf("unsupported host: %v", err)
	}
	after, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unsupported update changed the source")
	}
}
