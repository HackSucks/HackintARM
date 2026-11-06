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

func TestRootReplacementCommitAndDiscard(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{true: "commit", false: "discard"}[commit], func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := root.WriteFile("source", []byte("old"), 0751); err != nil {
				t.Fatal(err)
			}
			if err := root.Link("source", "neighbour"); err != nil {
				t.Fatal(err)
			}
			source, err := root.Open("source")
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			before, err := source.Stat()
			if err != nil {
				t.Fatal(err)
			}
			other, err := root.Stat("neighbour")
			if err != nil || !os.SameFile(before, other) {
				t.Fatalf("initial identity: %v", err)
			}
			r, err := PrepareReplacementAt(source, root, ".")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if filepath.IsAbs(r.Path) {
				t.Fatal("absolute staging path", r.Path)
			}
			if _, err := r.File.WriteAt([]byte("new"), 0); err != nil {
				t.Fatal(err)
			}
			if err := r.File.Truncate(3); err != nil {
				t.Fatal(err)
			}
			if err := r.RestoreMetadata(); err != nil {
				t.Fatal(err)
			}
			if err := r.File.Sync(); err != nil {
				t.Fatal(err)
			}
			if err := r.File.Close(); err != nil {
				t.Fatal(err)
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			if commit {
				if err := root.Rename(r.Path, "source"); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(r.RestoreMetadata(), os.ErrClosed) {
				t.Fatal("closed replacement accepted")
			}
			got, err := root.ReadFile("source")
			want := "old"
			if commit {
				want = "new"
			}
			if err != nil || string(got) != want {
				t.Fatalf("source = %q, %v", got, err)
			}
			got, err = root.ReadFile("neighbour")
			if err != nil || string(got) != "old" {
				t.Fatalf("neighbour = %q, %v", got, err)
			}
			after, err := root.Stat("source")
			if err != nil || os.SameFile(before, after) == commit || after.Mode() != before.Mode() {
				t.Fatalf("identity/mode: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 2 {
				t.Fatalf("cleanup: %v %v", entries, err)
			}
		})
	}
}

func TestRootReplacementContainmentAndRenamedRoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "original")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// Open relative to a parent so every operation uses the same root APIs.
	parentRoot, err := os.OpenRoot(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer parentRoot.Close()
	root, err := parentRoot.OpenRoot(filepath.Base(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("source", []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := root.Open("source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, parent := range []string{"..", filepath.Dir(dir), "missing"} {
		if r, err := PrepareReplacementAt(source, root, parent); err == nil {
			r.Close()
			t.Fatal("accepted", parent)
		}
	}
	if runtime.GOOS != "windows" {
		if err := root.Symlink(t.TempDir(), "outside"); err != nil {
			t.Fatal(err)
		}
		if r, err := PrepareReplacementAt(source, root, "outside"); err == nil {
			r.Close()
			t.Fatal("escaped root")
		}
	}
	// Move the root and plant a decoy at its old pathname. All staging must use
	// the opened directory; source.Name and root.Name are not authority to reopen.
	moved := dir + "-moved"
	if err := parentRoot.Rename(filepath.Base(dir), filepath.Base(moved)); err != nil {
		// Windows disallows moving this open directory, including with
		// delete-sharing handles. Go's TestRootRenameAfterOpen excludes it
		// for the same reason. Still exercise containment and staging here.
		if runtime.GOOS != "windows" || !errors.Is(err, os.ErrPermission) {
			t.Fatal(err)
		}
		moved = dir
	} else {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	r, err := PrepareReplacementAt(source, root, ".")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := os.Stat(filepath.Join(moved, r.Path)); err != nil {
		t.Fatal(err)
	}
	if moved != dir {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("decoy touched: %v %v", entries, err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRootReplacementFailurePreservesSource(t *testing.T) {
	source := heldfixture.Source(t, 0600)
	before, err := os.ReadFile(source.Name())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	r, err := PrepareReplacementAt(source, root, ".")
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.RestoreMetadata(); err == nil {
		t.Fatal("closed source accepted")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(source.Name())
	if err != nil || !bytes.Equal(got, before) {
		t.Fatalf("source changed: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging leaked: %v %v", entries, err)
	}
	if _, err := PrepareReplacementAt(source, root, "."); err == nil {
		t.Fatal("closed source accepted")
	}
	f, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := PrepareReplacementAt(f, root, "."); !errors.Is(err, ErrUnsupportedReplacement) {
		t.Fatal(err)
	}
}
