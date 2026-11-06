package hostdata

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
)

func TestReplacementPreservesSourceAndMode(t *testing.T) {
	for _, mode := range []os.FileMode{0751, 0551} {
		t.Run(mode.String(), func(t *testing.T) {
			source := heldfixture.Source(t, mode)
			before, err := source.Stat()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "replacement")
			r, err := PrepareReplacement(source, filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })
			if _, err := r.File.WriteAt([]byte("changed"), 0); err != nil {
				t.Fatal(err)
			}
			if err := r.File.Truncate(7); err != nil {
				t.Fatal(err)
			}
			if err := r.RestoreMetadata(); err != nil {
				t.Fatal(err)
			}
			after, err := r.File.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if os.SameFile(before, after) {
				t.Fatal("replacement shares source inode")
			}
			if after.Mode() != before.Mode() {
				t.Fatalf("mode = %v; want %v", after.Mode(), before.Mode())
			}
			original, err := os.ReadFile(source.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(original, []byte("original contents longer than the replacement")) {
				t.Fatal("source changed")
			}
			got, err := os.ReadFile(r.File.Name())
			if err != nil || string(got) != "changed" {
				t.Fatalf("replacement = %q, %v", got, err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 0 {
				t.Fatalf("staging not removed: %v, %v", entries, err)
			}
		})
	}
}

func TestReplacementRejectsInvalidSourcesAndDestinations(t *testing.T) {
	source := heldfixture.Source(t, 0600)
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{path, path + "\x00", filepath.Join(path, "child")} {
		if r, err := PrepareReplacement(source, destination); err == nil {
			_ = r.File.Close()
			t.Errorf("accepted invalid destination %q", destination)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "keep" {
		t.Fatalf("existing destination changed: %q, %v", got, err)
	}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if _, err := PrepareReplacement(dir, path); !errors.Is(err, ErrUnsupportedReplacement) {
		t.Fatalf("directory: %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareReplacement(source, filepath.Dir(path)); err == nil {
		t.Fatal("accepted closed source")
	}
}

func TestReplacementMetadataFailureLeavesSource(t *testing.T) {
	source := heldfixture.Source(t, 0600)
	r, err := PrepareReplacement(source, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.File.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.RestoreMetadata(); err == nil {
		t.Fatal("accepted closed destination")
	}
	if _, err := source.Stat(); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "darwin" {
		r, err := PrepareReplacement(source, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		if err := r.RestoreMetadata(); err == nil {
			t.Fatal("accepted closed source")
		}
	}
}
