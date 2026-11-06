package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestMetadataParentComponents(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub/deep"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub/file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"route": "sub/deep", "chain": "route/..", "loop": "loop", "up": "..", "absolute": t.TempDir()} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, want := range map[string]string{".": ".", "sub/.": "sub", "sub//deep": "sub/deep", "route/..": "sub", "route/../..": ".", "chain": "sub", "chain/deep/..": "sub"} {
		got, err := metadataParentPath(root, name)
		if err != nil || filepath.ToSlash(got) != want {
			t.Fatal(name, got, want, err)
		}
	}
	for name, want := range map[string]error{"missing/..": os.ErrNotExist, "sub/file/..": syscall.ENOTDIR, "loop": syscall.ELOOP, "up": os.ErrInvalid, "absolute": os.ErrInvalid, "..": os.ErrInvalid} {
		if _, err := metadataParentPath(root, name); !errors.Is(err, want) {
			t.Fatal(name, want, err)
		}
	}
	// Public operations must not let Windows lexical cleaning erase a missing
	// directory or a symlink traversal that leaves the root before the leaf.
	for _, name := range []string{"missing/../sub/file", "up/../sub/file", "loop/../sub/file"} {
		if _, err := ReadEntryType(root, name); err == nil {
			t.Fatal("unresolved parent accepted", name)
		}
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := metadataParentPath(root, "sub"); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}
