//go:build darwin || linux || windows

package hostdata

import (
	"errors"
	"os"

	"path/filepath"
	"runtime"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestMetadataStatIdentityAndContainment(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	for _, base := range []string{dir, outside} {
		if err := os.WriteFile(filepath.Join(base, "file"), []byte("metadata-only"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"alias": "file", "dangling": "missing", "internal": "sub", "outside": outside} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{".", "file", "sub", "alias", "dangling", "outside", "internal"} {
		t.Run(name, func(t *testing.T) {
			got, err := StatMetadata(root, name)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.Lstat(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(got, want) || got.Mode().Type() != want.Mode().Type() {
				t.Fatal("wrong entry", got, want)
			}
		})
	}
	for _, name := range []string{"missing", "internal/missing", "outside/file"} {
		if _, err := StatMetadata(root, name); err == nil {
			t.Fatal("missing/escaping accepted", name)
		}
	}
	if _, err := StatMetadata(root, "missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing error identity", err)
	}
	for _, name := range []string{"", "../file", filepath.Join(dir, "file")} {
		if _, err := StatMetadata(root, name); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(name, err)
		}
	}
	if _, err := StatMetadata(nil, "file"); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := StatMetadata(root, "file"); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed root", err)
	}
}

func metadataStatCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := cirunner.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, out)
	}
}

func TestMetadataStatDataReadDenied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(path)
	if err != nil {
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
	if f, err := root.Open("file"); err == nil {
		f.Close()
		t.Fatal("data denial ineffective")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	got, err := StatMetadata(root, "file")
	if err != nil {
		t.Fatal("metadata query requested data", err)
	}
	if !os.SameFile(original, got) || got.Size() != original.Size() {
		t.Fatal("wrong identity", got)
	}
	if runtime.GOOS == "windows" {
		f, err := OpenMetadataFileRead(root, "file")
		if err != nil {
			t.Fatal("metadata acquisition still requires data", err)
		}
		held, err := f.Stat()
		if err != nil || !os.SameFile(original, held) {
			t.Fatal("metadata acquisition identity", err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	restore()
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "unchanged" {
		t.Fatal("data changed", err)
	}
}

func TestMetadataStatDenied(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "sub")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "file")
	if err := os.WriteFile(path, nil, 0600); err != nil {
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
		// Directory-list permission grants child attribute visibility on NTFS.
		// Deny both sources rather than treating an ineffective ACE as qualification.
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
		t.Fatal("metadata denial ineffective", err)
	}
	restore()
	if _, err := StatMetadata(root, "sub/file"); err != nil {
		t.Fatal("restored metadata denied", err)
	}
}
