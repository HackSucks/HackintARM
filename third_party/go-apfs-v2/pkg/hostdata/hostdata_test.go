package hostdata

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestIsSpecial(t *testing.T) {
	special := []os.FileMode{
		os.ModeDevice,
		os.ModeDevice | os.ModeCharDevice,
		os.ModeNamedPipe,
		os.ModeSocket,
		os.ModeIrregular,
	}
	for _, mode := range special {
		if !IsSpecial(mode | 0o644) {
			t.Errorf("IsSpecial(%s) = false, want true", mode)
		}
	}

	ordinary := []os.FileMode{0o644, 0o755, os.ModeDir | 0o755, os.ModeSymlink | 0o777}
	for _, mode := range ordinary {
		if IsSpecial(mode) {
			t.Errorf("IsSpecial(%s) = true, want false", mode)
		}
	}
}

func TestIsACLName(t *testing.T) {
	for _, name := range []string{SecurityName, PosixACLAccessName} {
		if !IsACLName(name) {
			t.Errorf("IsACLName(%q) = false, want true", name)
		}
	}
	for _, name := range []string{ResourceForkName, DecmpfsName, "com.apple.quarantine", ""} {
		if IsACLName(name) {
			t.Errorf("IsACLName(%q) = true, want false", name)
		}
	}
}

// TestListXattrsOnPlainFile checks an ordinary file reads without error and
// yields a usable map on every platform.
//
// It deliberately does not assert the map is empty. macOS attaches
// com.apple.provenance to files as they are written, so "a file with no
// extended attributes" is not a state an ordinary macOS tree is in. That is
// worth knowing beyond this test: it is why reporting a dropped attribute must
// not, on its own, make a pack exit non-zero.
func TestListXattrsOnPlainFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(path, []byte("content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	attrs, err := ListXattrs(path)
	if err != nil {
		t.Fatalf("ListXattrs on a plain file: %v", err)
	}
	if attrs == nil {
		t.Fatal("ListXattrs returned a nil map; callers should be able to range over it")
	}
	t.Logf("a freshly written file carries %d extended attribute(s): %v", len(attrs), keysOf(attrs))
}

func keysOf(attrs map[string][]byte) []string {
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// TestListXattrsMissingFile checks a genuine failure is still reported as one.
func TestListXattrsMissingFile(t *testing.T) {
	if !XattrsSupported {
		t.Skip("extended attributes are not readable on this platform")
	}
	if _, err := ListXattrs(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("ListXattrs on a missing file returned no error")
	}
}

// TestLinkCountsNames checks hard links are distinguishable from separate
// files, which is what lets a walk report links rather than silently writing
// each name as its own copy.
func TestLinkCountsNames(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original.txt")
	if err := os.WriteFile(original, []byte("shared content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(original)
	if err != nil {
		t.Fatal(err)
	}
	before, ok := Link(info)
	if !ok {
		t.Skip("this platform does not expose inode identity")
	}
	if before.Links != 1 {
		t.Errorf("a file with one name reports %d links, want 1", before.Links)
	}

	linked := filepath.Join(dir, "linked.txt")
	if err := os.Link(original, linked); err != nil {
		t.Skipf("unable to create a hard link: %v", err)
	}

	info, err = os.Lstat(original)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := Link(info)
	if after.Links != 2 {
		t.Errorf("a file with two names reports %d links, want 2", after.Links)
	}

	linkedInfo, err := os.Lstat(linked)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := Link(linkedInfo)
	if other.Inode != after.Inode || other.Device != after.Device {
		t.Error("two names for one file report different inode identities")
	}

	// A separate file with identical content must not look like a link.
	separate := filepath.Join(dir, "separate.txt")
	if err := os.WriteFile(separate, []byte("shared content\n"), 0644); err != nil {
		t.Fatal(err)
	}
	separateInfo, err := os.Lstat(separate)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := Link(separateInfo); id.Inode == after.Inode {
		t.Error("a separate file shares an inode with the linked pair")
	}
}
