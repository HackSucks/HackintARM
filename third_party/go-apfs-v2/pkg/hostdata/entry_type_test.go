//go:build darwin || linux || windows

package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEntryTypeContainment(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(dir, "sub"), outside} {
		if err := os.WriteFile(filepath.Join(d, "file"), []byte("unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"link": "sub/file", "dangling": "missing", "internal": "sub", "external": outside} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, want := range map[string]os.FileMode{".": os.ModeDir, "sub": os.ModeDir, "sub/file": 0, "internal/file": 0, "link": os.ModeSymlink, "dangling": os.ModeSymlink, "external": os.ModeSymlink} {
		got, err := ReadEntryType(root, name)
		if err != nil || got != want {
			t.Fatal(name, got, want, err)
		}
	}
	for _, name := range []string{"missing", "sub/missing"} {
		if _, err := ReadEntryType(root, name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal(name, err)
		}
	}
	if _, err := ReadEntryType(root, "external/file"); err == nil {
		t.Fatal("escaped root")
	}
	for _, name := range []string{"", "../file", filepath.Join(dir, "sub/file")} {
		if _, err := ReadEntryType(root, name); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(name, err)
		}
	}
	if _, err := ReadEntryType(nil, "file"); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEntryType(root, "sub/file"); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestEntryTypeAuthorization(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "sub")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "file")
	if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var restore func()
	switch runtime.GOOS {
	case "darwin":
		metadataStatCommand(t, "/bin/chmod", "+a", "everyone deny readattr", path)
		restore = func() { metadataStatCommand(t, "/bin/chmod", "-N", path) }
	case "windows":
		metadataStatCommand(t, "icacls", path, "/deny", "*S-1-1-0:(RA)")
		metadataStatCommand(t, "icacls", parent, "/deny", "*S-1-1-0:(RD)")
		restore = func() {
			metadataStatCommand(t, "icacls", parent, "/remove:d", "*S-1-1-0")
			metadataStatCommand(t, "icacls", path, "/remove:d", "*S-1-1-0")
		}
	case "linux":
		if err := os.Chmod(parent, 0000); err != nil {
			t.Fatal(err)
		}
		restore = func() {
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(restore)
	if _, err := StatMetadata(root, "sub/file"); !errors.Is(err, os.ErrPermission) {
		t.Fatal("denial ineffective", err)
	}
	if _, err := ReadEntryType(root, "sub/file"); !errors.Is(err, os.ErrPermission) {
		t.Fatal("attribute authorization bypassed", err)
	}
	restore()
	if mode, err := ReadEntryType(root, "sub/file"); err != nil || mode != 0 {
		t.Fatal(mode, err)
	}
}

func TestEntryTypeHeldRootRename(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "original")
	moved := filepath.Join(parent, "moved")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer parentRoot.Close()
	root, err := parentRoot.OpenRoot("original")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "file"), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadEntryType(root, "file"); err != nil || got != 0 {
		t.Fatal("query reopened stale root name", got, err)
	}
}

func TestEntryTypeParentComponents(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub/deep"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub/kind"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "kind"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"route": "sub/deep", "chain": "route/.."} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, want := range map[string]os.FileMode{
		"route/../kind": 0, "chain/kind": 0,
		"sub/": os.ModeDir, "sub/.": os.ModeDir, "route/..": os.ModeDir,
	} {
		got, err := ReadEntryType(root, name)
		if err != nil || got != want {
			t.Fatal("parent components changed selection", name, got, want, err)
		}
	}
	for name, open := range map[string]func(*os.Root, string) (*os.File, error){
		"content": OpenContentFileRead, "metadata": OpenMetadataFileRead,
	} {
		file, err := open(root, "route/../kind")
		if err != nil {
			t.Fatal(name, "shared opener changed selection", err)
		}
		info, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil || !info.Mode().IsRegular() {
			t.Fatal(name, info, statErr, closeErr)
		}
	}
	if _, err := ReadEntryType(root, "route/../kind/"); err == nil {
		t.Fatal("trailing separator accepted regular file")
	}
}
