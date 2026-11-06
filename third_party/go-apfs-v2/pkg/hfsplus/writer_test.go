package hfsplus

import (
	"bytes"
	"crypto/sha256"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"
)

// memWriterAt is an in-memory io.WriterAt that grows as needed.
type memWriterAt struct{ b []byte }

func (m *memWriterAt) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(m.b) {
		nb := make([]byte, end)
		copy(nb, m.b)
		m.b = nb
	}
	copy(m.b[off:], p)
	return len(p), nil
}

// sampleTree builds a representative directory tree: nested dirs, a small and
// a ~1 MiB file, a symlink, an executable and a unicode name.
func sampleTree() (*Entry, []byte) {
	big := bytes.Repeat([]byte("ABCDEFGH0123456789"), 60000) // ~1.03 MiB
	root := &Entry{Children: []*Entry{
		{Name: "hello.txt", Mode: 0o644, Data: []byte("hello world\n")},
		{Name: "big.bin", Mode: 0o644, Data: big},
		{Name: "run.sh", Mode: 0o755, Data: []byte("#!/bin/sh\necho hi\n")},
		{Name: "link", Mode: os.ModeSymlink | 0o755, Data: []byte("hello.txt")},
		{Name: "café", Mode: 0o644, Data: []byte("unicode name\n")},
		{Name: "empty.txt", Mode: 0o644, Data: nil},
		{Name: "sub", Mode: os.ModeDir | 0o755, Children: []*Entry{
			{Name: "nested.txt", Mode: 0o644, Data: []byte("nested\n")},
			{Name: "deep", Mode: os.ModeDir | 0o755, Children: []*Entry{
				{Name: "leaf.txt", Mode: 0o644, Data: []byte("leaf\n")},
			}},
		}},
	}}
	return root, big
}

func buildSampleImage(t *testing.T) ([]byte, []byte) {
	t.Helper()
	root, big := sampleTree()
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	w := &memWriterAt{}
	if err := CreateImage(w, 0, "TestVol", root, &CreateOptions{FixedTime: fixed}); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	return w.b, big
}

func TestWriteReadRoundTrip(t *testing.T) {
	img, big := buildSampleImage(t)

	v, err := New(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if v.Name() != "TestVol" {
		t.Errorf("volume name = %q, want TestVol", v.Name())
	}
	if !v.CaseSensitive() {
		t.Errorf("expected case-sensitive HFSX volume")
	}

	// fstest.TestFS validates the fs.FS contract and directory walking.
	//
	// "café" is spelled decomposed here because that is what the volume holds:
	// HFS+ stores names decomposed and a listing reports what is on disk, as
	// macOS does. Looking the file up by either spelling works -- the check
	// below does exactly that -- but TestFS compares listings by exact string.
	if err := fstest.TestFS(v,
		"hello.txt", "big.bin", "run.sh", "link", normalizeName("café"), "empty.txt",
		"sub/nested.txt", "sub/deep/leaf.txt",
	); err != nil {
		t.Errorf("fstest.TestFS: %v", err)
	}

	// A precomposed name resolves even though the volume stores it decomposed,
	// which is the whole point: a caller's string literal or a path handed over
	// by another system is normally precomposed.
	if _, err := fs.ReadFile(v, "café"); err != nil {
		t.Errorf("looking up a precomposed name: %v", err)
	}

	// Content checks.
	checkContent := func(name string, want []byte) {
		got, err := fs.ReadFile(v, name)
		if err != nil {
			t.Errorf("ReadFile(%q): %v", name, err)
			return
		}
		if sha256.Sum256(got) != sha256.Sum256(want) {
			t.Errorf("content mismatch for %q (got %d bytes, want %d)", name, len(got), len(want))
		}
	}
	checkContent("hello.txt", []byte("hello world\n"))
	checkContent("big.bin", big)
	checkContent("empty.txt", nil)
	checkContent("sub/deep/leaf.txt", []byte("leaf\n"))

	// Symlink target.
	target, err := v.Readlink("link")
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if target != "hello.txt" {
		t.Errorf("symlink target = %q, want hello.txt", target)
	}

	// Modes.
	checkMode := func(name string, want fs.FileMode) {
		info, err := fs.Stat(v, name)
		if err != nil {
			t.Errorf("Stat(%q): %v", name, err)
			return
		}
		if info.Mode() != want {
			t.Errorf("mode(%q) = %v, want %v", name, info.Mode(), want)
		}
	}
	checkMode("run.sh", 0o755)
	checkMode("hello.txt", 0o644)
	checkMode("sub", fs.ModeDir|0o755)
	checkMode("link", fs.ModeSymlink|0o755)

	// Directory structure.
	entries, err := fs.ReadDir(v, "sub")
	if err != nil {
		t.Fatalf("ReadDir(sub): %v", err)
	}
	if len(entries) != 2 || entries[0].Name() != "deep" || entries[1].Name() != "nested.txt" {
		t.Errorf("sub children = %v, want [deep nested.txt]", names(entries))
	}
}

func names(entries []fs.DirEntry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestWriteFromDirRoundTrip(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.txt"), []byte("alpha"))
	mustMkdir(t, filepath.Join(dir, "d"))
	mustWrite(t, filepath.Join(dir, "d", "b.txt"), []byte("bravo"))

	w := &memWriterAt{}
	if err := CreateImageFromDir(w, 0, "FromDir", dir, nil); err != nil {
		t.Fatalf("CreateImageFromDir: %v", err)
	}
	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := fs.ReadFile(v, "d/b.txt")
	if err != nil || string(got) != "bravo" {
		t.Errorf("d/b.txt = %q, %v; want bravo", got, err)
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
}
