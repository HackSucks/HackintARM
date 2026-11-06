package accesstime

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
)

func TestCopyAccessTimeInvalidFiles(t *testing.T) {
	source, target := heldfixture.Source(t, 0600), heldfixture.Source(t, 0600)
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	closed := heldfixture.Source(t, 0600)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	// Preserve the host's Stat error for a closed descriptor.
	_, closedErr := closed.Stat()
	var statErr *os.PathError
	if !errors.As(closedErr, &statErr) {
		t.Fatalf("closed descriptor stat: %v", closedErr)
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Link(source.Name(), link); err != nil {
		t.Fatal(err)
	}
	linked, err := os.Open(link)
	if err != nil {
		t.Fatal(err)
	}
	defer linked.Close()
	for _, tc := range []struct {
		name     string
		from, to *os.File
		want     error
	}{
		{"nil-source", nil, target, os.ErrInvalid},
		{"nil-target", source, nil, os.ErrInvalid},
		{"directory-source", dir, target, os.ErrInvalid},
		{"directory-target", source, dir, os.ErrInvalid},
		{"same-file", source, source, os.ErrInvalid},
		{"same-inode", source, linked, os.ErrInvalid},
		{"closed-source", closed, target, statErr.Err},
		{"closed-target", source, closed, statErr.Err},
	} {
		t.Run(tc.name, func(t *testing.T) {
			beforeSource, err := source.Stat()
			if err != nil {
				t.Fatal(err)
			}
			beforeTarget, err := target.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if err := CopyAccessTime(tc.from, tc.to); !errors.Is(err, tc.want) {
				t.Fatalf("invalid files: %v", err)
			}
			afterSource, err := source.Stat()
			if err != nil {
				t.Fatal(err)
			}
			afterTarget, err := target.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(beforeSource.Sys(), afterSource.Sys()) || !reflect.DeepEqual(beforeTarget.Sys(), afterTarget.Sys()) {
				t.Fatal("rejected copy changed metadata")
			}
		})
	}
}

func TestCopyAccessTimeUnsupportedHost(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" || runtime.GOOS == "windows" {
		t.Skip("host supports access-time copying; covered by native tests")
	}
	source, target := heldfixture.Source(t, 0600), heldfixture.Source(t, 0600)
	beforeSource, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	beforeTarget, err := target.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := CopyAccessTime(source, target); !errors.Is(err, ErrAccessTimeUnsupported) {
		t.Fatal(err)
	}
	afterSource, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	afterTarget, err := target.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeSource.Sys(), afterSource.Sys()) || !reflect.DeepEqual(beforeTarget.Sys(), afterTarget.Sys()) {
		t.Fatal("unsupported copy changed metadata")
	}
}
