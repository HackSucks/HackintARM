// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// wantEntry is an expected file system path collected from the input tree.
type wantEntry struct {
	isDir bool
	data  []byte
}

// collectWants walks an input Entry tree and records the expected fs.WalkDir
// path set (relative, "." for root) with each file's content.
func collectWants(root *apfswrite.Entry) map[string]wantEntry {
	want := map[string]wantEntry{".": {isDir: true}}
	var rec func(prefix string, es []*apfswrite.Entry)
	rec = func(prefix string, es []*apfswrite.Entry) {
		for _, e := range es {
			p := e.Name
			if prefix != "" {
				p = prefix + "/" + e.Name
			}
			if e.Mode.IsDir() {
				want[p] = wantEntry{isDir: true}
				rec(p, e.Children)
			} else {
				want[p] = wantEntry{data: e.Data}
			}
		}
	}
	rec("", root.Children)
	return want
}

// walkAndAssert opens the image with the MIT reader and asserts that fs.WalkDir
// visits exactly the expected path set, that directories are directories, and
// that each file's content sha256 matches.
func walkAndAssert(t *testing.T, img fs.FS, want map[string]wantEntry) {
	t.Helper()
	got := map[string]bool{}
	err := fs.WalkDir(img, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		got[p] = true
		w, ok := want[p]
		if !ok {
			t.Errorf("unexpected path %q", p)
			return nil
		}
		if d.IsDir() != w.isDir {
			t.Errorf("path %q: IsDir=%v, want %v", p, d.IsDir(), w.isDir)
		}
		if !w.isDir {
			data, err := fs.ReadFile(img, p)
			if err != nil {
				t.Errorf("ReadFile %q: %v", p, err)
				return nil
			}
			if sha256.Sum256(data) != sha256.Sum256(w.data) {
				t.Errorf("path %q: content mismatch (got %d bytes, want %d)", p, len(data), len(w.data))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	for p := range want {
		if !got[p] {
			t.Errorf("missing path %q (never visited)", p)
		}
	}
}

// openVolume creates the container and returns the first volume as an fs.FS.
func openVolume(t *testing.T, opts *apfswrite.CreateOptions) *apfs.Volume {
	t.Helper()
	const size = 32 * 1024 * 1024
	img := &memImage{}
	if err := apfswrite.CreateContainer(img, size, opts); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	container, err := apfs.Open(img, &apfs.OpenOptions{})
	if err != nil {
		t.Fatalf("apfs.Open: %v", err)
	}
	volumes, err := container.Volumes()
	if err != nil {
		t.Fatalf("Volumes: %v", err)
	}
	if len(volumes) != 1 {
		t.Fatalf("volume count = %d, want 1", len(volumes))
	}
	return volumes[0]
}

// TestCreateContainerWithTree writes a nested directory tree with several files
// (including one two levels deep), reads it back with the MIT reader, walks it
// with fs.WalkDir and asserts every path and file sha256. Runs on every OS.
func TestCreateContainerWithTree(t *testing.T) {
	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "readme.txt", Data: []byte("top-level readme\n")},
		{Name: "notes.md", Data: []byte("# notes\nsome content here\n")},
		{Name: "docs", Mode: fs.ModeDir, Children: []*apfswrite.Entry{
			{Name: "guide.txt", Data: []byte("a guide inside docs\n")},
			{Name: "sub", Mode: fs.ModeDir, Children: []*apfswrite.Entry{
				{Name: "deep.txt", Data: []byte("two levels deep content\n")},
				{Name: "deep2.bin", Data: bytes.Repeat([]byte{0xAB}, 512)},
			}},
		}},
		{Name: "empty_dir", Mode: fs.ModeDir},
	}}

	v := openVolume(t, &apfswrite.CreateOptions{VolumeName: "TreeVol", Root: root})
	walkAndAssert(t, v, collectWants(root))
}

// TestCreateContainerMultiLeafFSTree writes enough files that the file-system tree can
// no longer fit in a single leaf node, forcing B-tree growth to a 2-level tree,
// then verifies the whole tree still reads back with matching sha256s.
func TestCreateContainerMultiLeafFSTree(t *testing.T) {
	const nFiles = 60
	children := make([]*apfswrite.Entry, 0, nFiles)
	for i := 0; i < nFiles; i++ {
		content := []byte(fmt.Sprintf("file number %d with some distinct content padding %d\n", i, i*7))
		children = append(children, &apfswrite.Entry{
			Name: fmt.Sprintf("file_%03d.txt", i),
			Data: content,
		})
	}
	// Add a nested directory with a couple more files for good measure.
	children = append(children, &apfswrite.Entry{Name: "nested", Mode: fs.ModeDir, Children: []*apfswrite.Entry{
		{Name: "a.txt", Data: []byte("nested a\n")},
		{Name: "b.txt", Data: []byte("nested b\n")},
	}})
	root := &apfswrite.Entry{Children: children}

	v := openVolume(t, &apfswrite.CreateOptions{VolumeName: "MultiLeaf", Root: root})
	walkAndAssert(t, v, collectWants(root))

	// Sanity: the root really does list all the top-level entries.
	entries, err := v.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != nFiles+1 {
		t.Errorf("root entries = %d, want %d", len(entries), nFiles+1)
	}
}
