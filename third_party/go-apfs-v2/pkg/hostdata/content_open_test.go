//go:build darwin || linux || windows

package hostdata

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestContentOpenIdentityAndContainment(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []string{filepath.Join(dir, "sub"), outside} {
		if err := os.WriteFile(filepath.Join(parent, "file"), []byte("unchanged"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"alias": "sub/file", "dangling": "missing", "internal": "sub", "outside": outside} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	original, err := os.Stat(filepath.Join(dir, "sub/file"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sub/file", "internal/file"} {
		f, err := OpenContentFileRead(root, name)
		if err != nil {
			t.Fatal(name, err)
		}
		st, err := f.Stat()
		if err != nil || !os.SameFile(st, original) {
			t.Fatal("wrong identity", err)
		}
		data, err := io.ReadAll(f)
		if err != nil || string(data) != "unchanged" {
			t.Fatal("content", err, string(data))
		}
		if _, err := f.WriteAt([]byte("x"), 0); err == nil {
			t.Fatal("reader allowed writes")
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"alias", "dangling", "outside/file", "missing"} {
		if f, err := OpenContentFileRead(root, name); err == nil {
			f.Close()
			t.Fatal("unsafe or missing file accepted", name)
		}
	}
	for _, name := range []string{".", "sub"} {
		if _, err := OpenContentFileRead(root, name); !errors.Is(err, ErrContentType) {
			t.Fatal("directory accepted", name, err)
		}
	}
	if _, err := OpenContentFileRead(root, "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing identity", err)
	}
	for _, name := range []string{"", "../file", filepath.Join(dir, "sub/file")} {
		if _, err := OpenContentFileRead(root, name); !errors.Is(err, os.ErrInvalid) {
			t.Fatal("invalid path", name, err)
		}
	}
	if _, err := OpenContentFileRead(nil, "file"); !errors.Is(err, os.ErrInvalid) {
		t.Fatal("nil root", err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenContentFileRead(root, "sub/file"); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed root", err)
	}
}

func TestContentOpenDescriptorLifecycle(t *testing.T) {
	if _, err := openContentAt(nil, "file"); err == nil {
		t.Fatal("nil parent accepted")
	}
	parent, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openContentAt(parent, "bad\x00name"); err == nil {
		t.Fatal("invalid basename accepted")
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openContentAt(parent, "file"); err == nil {
		t.Fatal("closed parent", err)
	}
	if _, err := checkContentFile(parent); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed content descriptor", err)
	}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkContentFile(dir); !errors.Is(err, ErrContentType) {
		t.Fatal("wrong type", err)
	}
	// A second Close must report the Go lifetime sentinel on every host.
	// Windows directory Stat instead returns native ERROR_INVALID_HANDLE.
	if err := dir.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("rejected descriptor leaked", err)
	}
}

func TestContentOpenDataDenial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
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
		metadataStatCommand(t, "/bin/chmod", "+a", "everyone deny read", path)
		restore = func() { metadataStatCommand(t, "/bin/chmod", "-N", path) }
	case "windows":
		metadataStatCommand(t, "icacls", path, "/deny", "*S-1-1-0:(RD)")
		restore = func() { metadataStatCommand(t, "icacls", path, "/remove:d", "*S-1-1-0") }
	case "linux":
		if err := os.Chmod(path, 0000); err != nil {
			t.Fatal(err)
		}
		restore = func() {
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(restore)
	if f, err := os.Open(path); err == nil {
		f.Close()
		t.Fatal("data denial ineffective")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	if f, err := OpenContentFileRead(root, "file"); err == nil {
		f.Close()
		t.Fatal("content reader bypassed data denial")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatal("lost permission identity", err)
	}
	restore()
	f, err := OpenContentFileRead(root, "file")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil || string(data) != "unchanged" {
		t.Fatal("denial changed data", err)
	}
}
