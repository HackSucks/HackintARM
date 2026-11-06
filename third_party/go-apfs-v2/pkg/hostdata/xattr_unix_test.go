//go:build darwin || linux

package hostdata

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// setXattr attaches an attribute to path, skipping the test when the file
// system will not take one.
func setXattr(t *testing.T, path, name string, value []byte) {
	t.Helper()
	if err := unix.Lsetxattr(path, name, value, 0); err != nil {
		t.Skipf("unable to set %s on %s: %v", name, path, err)
	}
}

// TestListXattrsReadsValues checks attributes are read back whole, with their
// values and not just their names, including a value large enough to exercise
// the two-call size-then-read sequence.
func TestListXattrsReadsValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attributed.txt")
	if err := os.WriteFile(path, []byte("content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	want := map[string][]byte{
		"user.small":    []byte("v"),
		"user.ordinary": []byte("a moderately sized value"),
		"user.large":    bytes.Repeat([]byte("0123456789"), 400), // 4 KB
		"user.empty":    {},
	}
	// Linux only permits the user.* namespace for unprivileged writes; darwin
	// takes any name, so the same names work on both.
	for name, value := range want {
		setXattr(t, path, name, value)
	}

	attrs, err := ListXattrs(path)
	if err != nil {
		t.Fatalf("ListXattrs: %v", err)
	}
	for name, value := range want {
		got, ok := attrs[name]
		if !ok {
			t.Errorf("%s missing from the listing", name)
			continue
		}
		if !bytes.Equal(got, value) {
			t.Errorf("%s = %d bytes, want %d", name, len(got), len(value))
		}
	}
}

// TestListXattrsDoesNotFollowSymlinks checks a symbolic link reports its own
// attributes rather than its target's. A link and its target are different
// objects, and conflating them would attribute one file's metadata to another.
func TestListXattrsDoesNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link")

	if err := os.WriteFile(target, []byte("content\n"), 0644); err != nil {
		t.Fatal(err)
	}
	setXattr(t, target, "user.on_target", []byte("target value"))
	if err := os.Symlink("target.txt", link); err != nil {
		t.Fatal(err)
	}

	attrs, err := ListXattrs(link)
	if err != nil {
		t.Fatalf("ListXattrs on a symlink: %v", err)
	}
	if _, ok := attrs["user.on_target"]; ok {
		t.Error("listing a symlink returned its target's attributes; the L-prefixed calls should not follow links")
	}
}
