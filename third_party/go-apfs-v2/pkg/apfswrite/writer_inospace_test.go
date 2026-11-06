// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// A volume group's two members share one inode-number space, divided at
// UNIFIED_ID_SPACE_MARK: the data volume numbers below it, the system volume at
// or above it, so a number identifies a file across the pair. Setting
// APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE takes on that obligation, and the writer
// sets it for every grouped volume. Before this the writer set the flag and
// numbered from 16 regardless, putting the system volume's files in the data
// volume's half.
//
// The reserved numbers below MIN_USER_INO_NUM stay where they are; only user
// inodes move. See inoBaseFor for the fsck_apfs evidence behind that, which is
// what these tests lock in.

var testGroupID = [16]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

// groupedTree has a nested directory, so the check covers an entry whose parent
// is itself an allocated number rather than only the root's direct children.
func groupedTree() *apfswrite.Entry {
	return &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "hello.txt", Data: []byte("hello\n")},
		{Name: "dir", Mode: fs.ModeDir, Children: []*apfswrite.Entry{
			{Name: "nested.txt", Data: []byte("nested\n")},
		}},
	}}
}

// groupedVolume returns the system half of a complete volume group. A group is
// a system/data pair, so both halves are written even when only one is being
// examined.
func groupedVolume(t *testing.T) *apfs.Volume {
	t.Helper()
	return groupedPair(t)[0]
}

// groupedPair writes a system/data group and returns both volumes in order.
func groupedPair(t *testing.T) []*apfs.Volume {
	t.Helper()
	img := &memImage{}
	err := apfswrite.CreateContainer(img, 1024*1024*1024, &apfswrite.CreateOptions{
		Volumes: []apfswrite.VolumeSpec{
			{Name: "GROUP", Role: apfs.VolumeRoleSystem, VolumeGroupID: testGroupID, Root: groupedTree()},
			{Name: "GROUPDATA", Role: apfs.VolumeRoleData, VolumeGroupID: testGroupID, Root: groupedTree()},
		},
	})
	if err != nil {
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
	if len(volumes) != 2 {
		t.Fatalf("container holds %d volumes, want 2", len(volumes))
	}
	return volumes
}

// TestVolumeGroupHalvesUseOppositeInodeSpaces is what the single-volume tests
// could only assert one side of: the two halves share one inode-number space,
// divided at UNIFIED_ID_SPACE_MARK, so a number identifies a file across the
// pair. Until a group could have both halves this was untestable.
func TestVolumeGroupHalvesUseOppositeInodeSpaces(t *testing.T) {
	volumes := groupedPair(t)

	for i, tc := range []struct {
		name  string
		above bool
	}{
		{"system", true},
		{"data", false},
	} {
		root, err := volumes[i].RootDirectory()
		if err != nil {
			t.Fatalf("%s: RootDirectory: %v", tc.name, err)
		}
		n, err := root.NumberOfSubFileEntries()
		if err != nil {
			t.Fatalf("%s: NumberOfSubFileEntries: %v", tc.name, err)
		}
		for j := range n {
			child, err := root.SubFileEntryByIndex(j)
			if err != nil {
				t.Fatalf("%s: SubFileEntryByIndex(%d): %v", tc.name, j, err)
			}
			id, err := child.Identifier()
			if err != nil {
				t.Fatalf("%s: Identifier: %v", tc.name, err)
			}
			if above := id >= apfs.UnifiedIDSpaceMark; above != tc.above {
				childName, _ := child.UTF8Name()
				t.Errorf("%s half: %s has inode %#x, which is %s the mark; want %s",
					tc.name, childName, id,
					map[bool]string{true: "above", false: "below"}[above],
					map[bool]string{true: "above", false: "below"}[tc.above])
			}
		}
	}
}

// TestSystemVolumeInGroupNumbersUserInodesAboveMark is the bug: every inode the
// volume allocates must land in the system half of the shared space.
func TestSystemVolumeInGroupNumbersUserInodesAboveMark(t *testing.T) {
	vol := groupedVolume(t)

	root, err := vol.RootDirectory()
	if err != nil {
		t.Fatalf("RootDirectory: %v", err)
	}

	floor := apfs.UnifiedIDSpaceMark + apfs.MinUserInoNum
	var seen int
	var walk func(dir *apfs.FileEntry, path string)
	walk = func(dir *apfs.FileEntry, path string) {
		n, err := dir.NumberOfSubFileEntries()
		if err != nil {
			t.Fatalf("NumberOfSubFileEntries(%s): %v", path, err)
		}
		for i := range n {
			child, err := dir.SubFileEntryByIndex(i)
			if err != nil {
				t.Fatalf("SubFileEntryByIndex(%s, %d): %v", path, i, err)
			}
			name, err := child.UTF8Name()
			if err != nil {
				t.Fatalf("UTF8Name: %v", err)
			}
			id, err := child.Identifier()
			if err != nil {
				t.Fatalf("Identifier(%s/%s): %v", path, name, err)
			}
			if id < floor {
				t.Errorf("%s/%s has inode %#x, below the system volume's floor %#x; "+
					"it is in the data volume's half of the shared space", path, name, id, floor)
			}
			seen++
			if mode, err := child.FileMode(); err == nil && mode&0o170000 == 0o040000 {
				walk(child, path+"/"+name)
			}
		}
	}
	walk(root, "")

	if seen != 3 {
		t.Fatalf("walked %d entries, want 3; the tree was not read back whole", seen)
	}
}

// TestSystemVolumeInGroupKeepsReservedInodesUnshifted pins the half of the rule
// that the spec states the other way round. The spec says the system volume
// reserves "each of the inode numbers listed above but with
// UNIFIED_ID_SPACE_MARK added to them", which would put the root at
// 0x0800000000000002; fsck_apfs rejects a volume written that way. See
// inoBaseFor.
func TestSystemVolumeInGroupKeepsReservedInodesUnshifted(t *testing.T) {
	vol := groupedVolume(t)

	root, err := vol.RootDirectory()
	if err != nil {
		t.Fatalf("RootDirectory: %v", err)
	}
	id, err := root.Identifier()
	if err != nil {
		t.Fatalf("Identifier: %v", err)
	}
	if id != apfs.RootDirInoNum {
		t.Errorf("root inode = %#x, want %d", id, apfs.RootDirInoNum)
	}

	parent, err := root.ParentIdentifier()
	if err != nil {
		t.Fatalf("ParentIdentifier: %v", err)
	}
	if parent != apfs.RootDirParent {
		t.Errorf("root's parent = %#x, want %d; shifting ROOT_DIR_PARENT makes "+
			"fsck_apfs report both special dentries as orphan directory records",
			parent, apfs.RootDirParent)
	}
}

// TestSystemVolumeInGroupContentsAreReadable checks the shift did not cost
// discoverability: paths still resolve and contents still come back.
func TestSystemVolumeInGroupContentsAreReadable(t *testing.T) {
	vol := groupedVolume(t)

	for path, want := range map[string]string{
		"hello.txt":      "hello\n",
		"dir/nested.txt": "nested\n",
	} {
		data, err := vol.ReadFile(path)
		if err != nil {
			t.Errorf("ReadFile(%q): %v", path, err)
			continue
		}
		if string(data) != want {
			t.Errorf("ReadFile(%q) = %q, want %q", path, data, want)
		}
	}
}

// TestUngroupedVolumeKeepsOrdinaryInodeNumbers is the regression guard: the
// shift applies only where the feature flag obliges it, so every image this
// tool already produces is unchanged.
func TestUngroupedVolumeKeepsOrdinaryInodeNumbers(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts apfswrite.CreateOptions
	}{
		{"no role, no group", apfswrite.CreateOptions{VolumeName: "PLAIN"}},
		{"system role, no group", apfswrite.CreateOptions{VolumeName: "SYS", Role: apfs.VolumeRoleSystem}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			opts.Root = groupedTree()
			vol := openVolume(t, &opts)

			root, err := vol.RootDirectory()
			if err != nil {
				t.Fatalf("RootDirectory: %v", err)
			}
			n, err := root.NumberOfSubFileEntries()
			if err != nil {
				t.Fatalf("NumberOfSubFileEntries: %v", err)
			}
			for i := range n {
				child, err := root.SubFileEntryByIndex(i)
				if err != nil {
					t.Fatalf("SubFileEntryByIndex(%d): %v", i, err)
				}
				id, err := child.Identifier()
				if err != nil {
					t.Fatalf("Identifier: %v", err)
				}
				if id >= apfs.UnifiedIDSpaceMark {
					name, _ := child.UTF8Name()
					t.Errorf("%s has inode %#x on an ungrouped volume; "+
						"only a volume group's system half numbers above the mark", name, id)
				}
			}
		})
	}
}
