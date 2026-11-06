// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// The tests in this file began as measurements of the writer's capacity
// limits: each searched for the file count at which the writer refused a tree
// or wrote an unreadable one. The trees now grow to any height, so the tests
// instead write volumes far past those old limits and read them back, and
// report what they wrote as a LIMIT line (test output and, under GitHub
// Actions, the step summary).

var limitSummaryHeaderWritten bool

// reportLimit records a measured limit.
func reportLimit(t *testing.T, name string, format string, args ...any) {
	t.Helper()
	value := fmt.Sprintf(format, args...)
	t.Logf("LIMIT %s = %s", name, value)

	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	if !limitSummaryHeaderWritten {
		fmt.Fprintf(f, "\n### apfswrite measured limits (%s/%s)\n", runtime.GOOS, runtime.GOARCH)
		limitSummaryHeaderWritten = true
	}
	fmt.Fprintf(f, "- `%s`: %s\n", name, value)
}

// flatTree returns a root holding n files named by name(i), each with a few
// bytes of distinct content.
func flatTree(n int, name func(i int) string) *apfswrite.Entry {
	children := make([]*apfswrite.Entry, n)
	for i := range children {
		children[i] = &apfswrite.Entry{
			Name: name(i),
			Data: []byte(fmt.Sprintf("file %d\n", i)),
		}
	}
	return &apfswrite.Entry{Children: children}
}

// build writes a container for root and returns the image, or the writer's
// error.
func build(root *apfswrite.Entry, snapshots []apfswrite.SnapshotSpec) (*memImage, error) {
	img := &memImage{}
	err := apfswrite.CreateContainer(img, 0, &apfswrite.CreateOptions{
		VolumeName: "Limits",
		Root:       root,
		Snapshots:  snapshots,
	})
	return img, err
}

// readsBack opens img with the reader and reports the first way in which its
// contents differ from root. Unlike walkAndAssert it returns the problem, so a
// caller can search for the point at which images stop being readable.
func readsBack(img *memImage, root *apfswrite.Entry) error {
	container, err := apfs.Open(img, &apfs.OpenOptions{})
	if err != nil {
		return fmt.Errorf("open container: %w", err)
	}
	volumes, err := container.Volumes()
	if err != nil {
		return fmt.Errorf("volumes: %w", err)
	}
	if len(volumes) != 1 {
		return fmt.Errorf("volume count = %d, want 1", len(volumes))
	}
	want := collectWants(root)
	seen := 0
	err = fs.WalkDir(volumes[0], ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		w, ok := want[p]
		if !ok {
			return fmt.Errorf("unexpected path %q", p)
		}
		seen++
		if w.isDir {
			return nil
		}
		f, err := volumes[0].Open(p)
		if err != nil {
			return fmt.Errorf("open %q: %w", p, err)
		}
		defer f.Close()
		got, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("read %q: %w", p, err)
		}
		if sha256.Sum256(got) != sha256.Sum256(w.data) {
			return fmt.Errorf("content of %q differs", p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(want) {
		return fmt.Errorf("walk visited %d paths, want %d", seen, len(want))
	}
	return nil
}

// TestManySmallFiles writes one flat directory of 50,000 small files -- far
// past the 850 the writer used to refuse at, when its file-system tree could
// be no more than two levels of 64 leaves -- and reads every one back.
func TestManySmallFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 50,000 files")
	}
	const n = 50_000
	root := flatTree(n, func(i int) string { return fmt.Sprintf("file%08d", i) })
	img, err := build(root, nil)
	if err != nil {
		t.Fatalf("%d files: %v", n, err)
	}
	checkImage(t, img, root)
	reportLimit(t, "fs-tree small files (12-byte names)", "%d files written and read back", n)
}

// TestManyLongNames writes 5,000 files with 255-byte names. Their directory
// entries make the file-system tree's index records long, which used to
// overflow a two-level tree's index root at 166 files.
func TestManyLongNames(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 5,000 long-named files")
	}
	const n = 5_000
	root := flatTree(n, func(i int) string {
		prefix := fmt.Sprintf("%08d", i)
		return prefix + strings.Repeat("n", 255-len(prefix))
	})
	img, err := build(root, nil)
	if err != nil {
		t.Fatalf("%d long-named files: %v", n, err)
	}
	checkImage(t, img, root)
	reportLimit(t, "fs-tree long names (255-byte names)", "%d files written and read back", n)
}

// TestSnapshotOfManyFiles snapshots a volume of 5,000 non-empty files. The
// snapshot owns the volume's populated extentref tree, which used to have to
// fit in one node, so snapshots were refused past 112 such files.
func TestSnapshotOfManyFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 5,000 files")
	}
	const n = 5_000
	root := flatTree(n, func(i int) string { return fmt.Sprintf("file%08d", i) })
	img, err := build(root, snapshotNames(2))
	if err != nil {
		t.Fatalf("%d files with snapshots: %v", n, err)
	}
	checkImage(t, img, root)
	reportLimit(t, "snapshot non-empty files", "%d files with 2 snapshots written and read back", n)
}

// TestExtentrefRootLeafBoundary writes every file count around the point where
// the extentref tree outgrows one root-leaf. At 111 and 112 non-empty files the
// writer used to overrun that root, sized as though it had no footer, and
// fsck_apfs rejected the tree ("Extent ref tree is invalid"); the reader never
// looks at it, so only checkNodeLayouts catches this here.
func TestExtentrefRootLeafBoundary(t *testing.T) {
	for n := 105; n <= 120; n++ {
		root := flatTree(n, func(i int) string { return fmt.Sprintf("file%08d", i) })
		img, err := build(root, nil)
		if err != nil {
			t.Fatalf("%d files: %v", n, err)
		}
		if _, err := apfswrite.CheckNodeLayouts(img.data); err != nil {
			t.Fatalf("%d files: %v", n, err)
		}
	}
}

// TestVolumesBeyondReservedOIDs writes two volumes whose file-system trees
// each have more non-root nodes than the 64 oids a volume reserves, so both
// take oids from past every volume's reservation, and reads both back.
func TestVolumesBeyondReservedOIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 7,000 files into a 1 GiB container")
	}
	roots := []*apfswrite.Entry{
		flatTree(3_000, func(i int) string { return fmt.Sprintf("a%08d", i) }),
		flatTree(4_000, func(i int) string { return fmt.Sprintf("b%08d", i) }),
	}
	img := &memImage{}
	err := apfswrite.CreateContainer(img, 1<<30, &apfswrite.CreateOptions{Volumes: []apfswrite.VolumeSpec{
		{Name: "One", Root: roots[0]},
		{Name: "Two", Root: roots[1], Snapshots: snapshotNames(1)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apfswrite.CheckNodeLayouts(img.data); err != nil {
		t.Fatal(err)
	}
	container, err := apfs.Open(img, &apfs.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	volumes, err := container.Volumes()
	if err != nil {
		t.Fatal(err)
	}
	if len(volumes) != 2 {
		t.Fatalf("%d volumes, want 2", len(volumes))
	}
	for i, v := range volumes {
		walkAndAssert(t, v, collectWants(roots[i]))
	}
}

// checkImage checks every B-tree node of img and reads its volume back.
func checkImage(t *testing.T, img *memImage, root *apfswrite.Entry) {
	t.Helper()
	nodes, err := apfswrite.CheckNodeLayouts(img.data)
	if err != nil {
		t.Fatal(err)
	}
	if err := readsBack(img, root); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d B-tree nodes checked", nodes)
}

// TestLookupAcrossManyDirectories opens files round-robin across more
// directories than the reader keeps name indexes for, so indexes are evicted
// and rebuilt between lookups, and on a case-insensitive volume looks each one
// up by a differently cased name as well.
func TestLookupAcrossManyDirectories(t *testing.T) {
	const dirs, perDir = 80, 50
	root := &apfswrite.Entry{}
	for d := range dirs {
		dir := &apfswrite.Entry{Name: fmt.Sprintf("dir%03d", d), Mode: fs.ModeDir}
		for f := range perDir {
			dir.Children = append(dir.Children, &apfswrite.Entry{
				Name: fmt.Sprintf("File%03d.txt", f),
				Data: fmt.Appendf(nil, "%d/%d\n", d, f),
			})
		}
		root.Children = append(root.Children, dir)
	}
	vol := openVolume(t, &apfswrite.CreateOptions{VolumeName: "Dirs", Root: root})
	for f := range perDir {
		for d := range dirs {
			want := fmt.Sprintf("%d/%d\n", d, f)
			for _, name := range []string{
				fmt.Sprintf("dir%03d/File%03d.txt", d, f),
				fmt.Sprintf("DIR%03d/file%03d.TXT", d, f),
			} {
				got, err := fs.ReadFile(vol, name)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if string(got) != want {
					t.Fatalf("%s holds %q, want %q", name, got, want)
				}
			}
		}
	}
	if _, err := fs.ReadFile(vol, "dir000/missing.txt"); err == nil {
		t.Fatal("a missing name was found")
	}

	// A mounted volume serves lookups concurrently, so the indexes are shared
	// state; run the lookups from several goroutines too (meaningful under
	// -race).
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range dirs * 4 {
				d, f := (g*7+i)%dirs, i%perDir
				name := fmt.Sprintf("dir%03d/File%03d.txt", d, f)
				got, err := fs.ReadFile(vol, name)
				if err == nil && string(got) != fmt.Sprintf("%d/%d\n", d, f) {
					err = fmt.Errorf("%s holds %q", name, got)
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
