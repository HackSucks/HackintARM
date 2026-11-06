// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"bytes"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// reproTree returns a tree exercising every path that stamps a timestamp:
// nested directories, a symbolic link, an entry with an explicit ModTime, an
// entry with none, an empty file and a multi-block file.
func reproTree(explicit time.Time) *apfswrite.Entry {
	return &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "dated.txt", Data: []byte("has an explicit time\n"), ModTime: explicit},
		{Name: "undated.txt", Data: []byte("has no time at all\n")},
		{Name: "empty.txt"},
		{Name: "big.bin", Data: bytes.Repeat([]byte("multi-block payload "), 1000)},
		{Name: "link", Mode: os.ModeSymlink, Data: []byte("dated.txt")},
		{Name: "sub", Mode: os.ModeDir, Children: []*apfswrite.Entry{
			{Name: "nested.txt", Data: []byte("two levels down\n"), ModTime: explicit},
			{Name: "deeper", Mode: os.ModeDir, Children: []*apfswrite.Entry{
				{Name: "leaf.txt", Data: []byte("three levels down\n")},
			}},
		}},
	}}
}

// buildImage builds a container into memory and returns its bytes.
func buildImage(t *testing.T, opts *apfswrite.CreateOptions) []byte {
	t.Helper()
	img := &memImage{}
	if err := apfswrite.CreateContainer(img, 32*1024*1024, opts); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	return img.data
}

// TestCreateContainerDeterministic builds the same container twice and requires
// the two images to be byte-identical. Before FixedTime existed the builder
// seeded its timestamp from time.Now(), which reached the volume superblock's
// formatted-by field and every directory entry's date_added, so two builds
// microseconds apart differed.
func TestCreateContainerDeterministic(t *testing.T) {
	explicit := time.Date(2023, time.March, 4, 5, 6, 7, 0, time.UTC)

	cases := []struct {
		name string
		opts apfswrite.CreateOptions
	}{
		{"defaults", apfswrite.CreateOptions{VolumeName: "REPRO", Root: reproTree(explicit)}},
		{"fixed time", apfswrite.CreateOptions{
			VolumeName: "REPRO",
			Root:       reproTree(explicit),
			FixedTime:  time.Date(2021, time.June, 1, 0, 0, 0, 0, time.UTC),
		}},
		{"case sensitive", apfswrite.CreateOptions{
			VolumeName:    "REPRO",
			Root:          reproTree(explicit),
			CaseSensitive: true,
		}},
		{"snapshot", apfswrite.CreateOptions{
			VolumeName: "REPRO",
			Root:       reproTree(explicit),
			Snapshots:  []apfswrite.SnapshotSpec{{Name: "snap-1"}},
		}},
		{"empty volume", apfswrite.CreateOptions{VolumeName: "REPRO"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := buildImage(t, &tc.opts)
			second := buildImage(t, &tc.opts)
			if !bytes.Equal(first, second) {
				t.Fatalf("two builds of the same container differ (%d vs %d bytes, first difference at offset %d)",
					len(first), len(second), firstDiff(first, second))
			}
		})
	}
}

// TestCreateContainerFixedTimeIsWired proves the knob does something: two
// builds that differ only in FixedTime must not produce the same bytes.
func TestCreateContainerFixedTimeIsWired(t *testing.T) {
	base := apfswrite.CreateOptions{VolumeName: "REPRO", Root: reproTree(time.Time{})}

	early := base
	early.FixedTime = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	late := base
	late.FixedTime = time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)

	if bytes.Equal(buildImage(t, &early), buildImage(t, &late)) {
		t.Fatal("containers built with different FixedTime are byte-identical; FixedTime is not reaching the image")
	}
}

// TestCreateContainerDefaultTime confirms an unset FixedTime resolves to
// DefaultTime rather than the wall clock, by comparing against an explicit one.
func TestCreateContainerDefaultTime(t *testing.T) {
	implicit := apfswrite.CreateOptions{VolumeName: "REPRO", Root: reproTree(time.Time{})}
	explicit := implicit
	explicit.FixedTime = apfswrite.DefaultTime

	if !bytes.Equal(buildImage(t, &implicit), buildImage(t, &explicit)) {
		t.Fatal("an unset FixedTime does not match an explicit DefaultTime")
	}
}

// TestCreateContainerClampsModTimes checks the SOURCE_DATE_EPOCH rule: with
// ClampModTimes set, an entry newer than FixedTime is written as FixedTime and
// an older entry keeps its own time. Without it, the newer time survives.
func TestCreateContainerClampsModTimes(t *testing.T) {
	fixed := time.Date(2022, time.July, 1, 12, 0, 0, 0, time.UTC)
	newer := fixed.Add(1 * time.Hour)
	older := fixed.Add(-1 * time.Hour)

	tree := func() *apfswrite.Entry {
		return &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "newer.txt", Data: []byte("from the future\n"), ModTime: newer},
			{Name: "older.txt", Data: []byte("from the past\n"), ModTime: older},
			{Name: "undated.txt", Data: []byte("no time\n")},
		}}
	}

	t.Run("clamped", func(t *testing.T) {
		vol := openVolume(t, &apfswrite.CreateOptions{
			VolumeName:    "CLAMP",
			Root:          tree(),
			FixedTime:     fixed,
			ClampModTimes: true,
		})
		assertModTime(t, vol, "newer.txt", fixed)
		assertModTime(t, vol, "older.txt", older)
		assertModTime(t, vol, "undated.txt", fixed)
	})

	t.Run("unclamped", func(t *testing.T) {
		vol := openVolume(t, &apfswrite.CreateOptions{
			VolumeName: "CLAMP",
			Root:       tree(),
			FixedTime:  fixed,
		})
		assertModTime(t, vol, "newer.txt", newer)
		assertModTime(t, vol, "older.txt", older)
		assertModTime(t, vol, "undated.txt", fixed)
	})
}

// assertModTime reads name back through the reader and compares its
// modification time against want.
func assertModTime(t *testing.T, vol fs.StatFS, name string, want time.Time) {
	t.Helper()
	info, err := vol.Stat(name)
	if err != nil {
		t.Fatalf("Stat(%q): %v", name, err)
	}
	if got := info.ModTime().UTC(); !got.Equal(want.UTC()) {
		t.Errorf("%s: mod time = %s, want %s", name, got, want.UTC())
	}
}

// firstDiff returns the offset of the first differing byte, or -1 when the two
// slices share a prefix and differ only in length.
func firstDiff(a, b []byte) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}
