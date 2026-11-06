package hostwalk

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// testEntry is a minimal stand-in for the writers' Entry types, so the walk can
// be tested without either of them.
type testEntry struct {
	name     string
	mode     os.FileMode
	data     []byte
	children []*testEntry
}

func mkTestEntry(n Node, children []*testEntry) *testEntry {
	return &testEntry{name: n.Name, mode: n.Mode, data: n.Data, children: children}
}

// paths returns every path in the tree, depth first, for comparison.
func paths(root *testEntry, prefix string) []string {
	var out []string
	for _, child := range root.children {
		p := child.name
		if prefix != "" {
			p = prefix + "/" + child.name
		}
		out = append(out, p)
		out = append(out, paths(child, p)...)
	}
	sort.Strings(out)
	return out
}

func TestWalkBuildsTheTree(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "top.txt"), "top\n")
	mustMkdir(t, filepath.Join(dir, "sub"))
	mustWrite(t, filepath.Join(dir, "sub", "nested.txt"), "nested\n")
	mustMkdir(t, filepath.Join(dir, "sub", "deep"))
	mustWrite(t, filepath.Join(dir, "sub", "deep", "leaf.txt"), "leaf\n")

	root, report, err := Walk(dir, nil, mkTestEntry)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	want := []string{"sub", "sub/deep", "sub/deep/leaf.txt", "sub/nested.txt", "top.txt"}
	if got := paths(root, ""); !equal(got, want) {
		t.Errorf("walked %v, want %v", got, want)
	}
	if report == nil {
		t.Fatal("Walk returned a nil report")
	}
	if !report.Lossless() && report.Count(fidelity.Xattr) == 0 {
		// Xattrs are off by default, so any loss here is unexpected.
		t.Errorf("a plain tree reported losses: %v", report.JSON())
	}
}

// TestWalkSkipsSpecialFiles is the behaviour that stops a pack hanging: a FIFO
// must be skipped and counted, not read.
func TestWalkSkipsSpecialFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs on Windows")
	}
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "regular.txt"), "content\n")
	if !makeFIFO(t, filepath.Join(dir, "pipe")) {
		t.Skip("unable to create a FIFO")
	}

	var warned []string
	root, report, err := Walk(dir, &Options{
		Warn: func(path string, kind fidelity.Kind, detail string) {
			if kind == fidelity.SpecialFile {
				warned = append(warned, path)
			}
		},
	}, mkTestEntry)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if got := paths(root, ""); !equal(got, []string{"regular.txt"}) {
		t.Errorf("walked %v, want just the regular file", got)
	}
	if got := report.Count(fidelity.SpecialFile); got != 1 {
		t.Errorf("special files counted = %d, want 1", got)
	}
	if report.EntriesSkipped() != 1 {
		t.Errorf("EntriesSkipped = %d, want 1", report.EntriesSkipped())
	}
	if !equal(warned, []string{"pipe"}) {
		t.Errorf("warned about %v, want [pipe]", warned)
	}
	if report.Lossless() {
		t.Error("a walk that skipped an entry claims to be lossless")
	}
}

// TestWalkReportsHardLinks checks the second and later names for one inode are
// reported, and the first is not: one of them is written, the rest become
// independent copies.
func TestWalkReportsHardLinks(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "a-original.txt")
	mustWrite(t, original, "shared\n")
	if err := os.Link(original, filepath.Join(dir, "b-link.txt")); err != nil {
		t.Skipf("unable to create a hard link: %v", err)
	}
	if err := os.Link(original, filepath.Join(dir, "c-link.txt")); err != nil {
		t.Skipf("unable to create a hard link: %v", err)
	}

	// Creating a link and recognizing one are separate capabilities. NTFS
	// supports hard links, but Windows does not expose inode identity through
	// os.FileInfo, so there they are indistinguishable from separate files —
	// which is what LinkIdentity reports and what the walk then cannot count.
	info, err := os.Lstat(original)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := hostdata.Link(info); !ok {
		t.Skip("this platform does not expose inode identity, so hard links cannot be recognized")
	}
	// A separate file with identical content must not be reported.
	mustWrite(t, filepath.Join(dir, "d-separate.txt"), "shared\n")

	_, report, err := Walk(dir, nil, mkTestEntry)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	// Three names, one inode: two of them are extra.
	if got := report.Count(fidelity.HardLink); got != 2 {
		t.Errorf("hard links counted = %d, want 2 (three names, one inode)", got)
	}
	// The links are still written, just not as links, so nothing was skipped.
	if got := report.EntriesSkipped(); got != 0 {
		t.Errorf("EntriesSkipped = %d, want 0; a collapsed link is still written", got)
	}
}

// TestWalkReportsXattrsOnlyWhenAsked checks the opt-in: reading attributes
// costs syscalls per entry, so a caller that does not ask gets no attribute
// counts rather than a false zero.
func TestWalkReportsXattrsOnlyWhenAsked(t *testing.T) {
	if !hostdata.XattrsSupported {
		t.Skip("extended attributes are not readable on this platform")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "attributed.txt")
	mustWrite(t, path, "content\n")
	if !setXattr(t, path, "user.marker", []byte("value")) {
		t.Skip("unable to set an extended attribute")
	}

	_, off, err := Walk(dir, &Options{Xattrs: false}, mkTestEntry)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if got := off.Count(fidelity.Xattr); got != 0 {
		t.Errorf("attributes counted = %d without Xattrs set, want 0", got)
	}

	_, on, err := Walk(dir, &Options{Xattrs: true}, mkTestEntry)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if got := on.Count(fidelity.Xattr); got == 0 {
		t.Error("no attributes counted with Xattrs set, want at least the one that was set")
	}
}

// TestWalkClassifiesAttributes checks a resource fork and an ACL are counted
// separately from ordinary attributes: losing file content is a different
// statement to losing metadata.
func TestWalkClassifiesAttributes(t *testing.T) {
	if !hostdata.XattrsSupported {
		t.Skip("extended attributes are not readable on this platform")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "forked.txt")
	mustWrite(t, path, "content\n")
	if !setXattr(t, path, hostdata.ResourceForkName, []byte("fork content")) {
		t.Skip("unable to set a resource fork attribute")
	}

	_, report, err := Walk(dir, &Options{Xattrs: true}, mkTestEntry)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if got := report.Count(fidelity.ResourceFork); got != 1 {
		t.Errorf("resource forks counted = %d, want 1", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
