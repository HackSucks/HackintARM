// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// TestCreateContainerHardLinks checks several names for one file share an
// inode, and that the content is stored once rather than copied per name.
func TestCreateContainerHardLinks(t *testing.T) {
	shared := []byte("shared content\n")

	vol := openVolume(t, &apfswrite.CreateOptions{
		VolumeName: "LINKS",
		Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "original.txt", Data: shared, LinkGroup: 1},
			{Name: "link-a.txt", Data: shared, LinkGroup: 1},
			{Name: "link-b.txt", Data: shared, LinkGroup: 1},
			{Name: "plain.txt", Data: []byte("not linked\n")},
			{Name: "sub", Mode: os.ModeDir, Children: []*apfswrite.Entry{
				{Name: "link-c.txt", Data: shared, LinkGroup: 1},
			}},
		}},
	})

	names := []string{"original.txt", "link-a.txt", "link-b.txt", "sub/link-c.txt"}

	var inode uint64
	for _, name := range names {
		entry, err := vol.FileEntryByPath(name)
		if err != nil {
			t.Fatalf("FileEntryByPath(%s): %v", name, err)
		}
		if inode == 0 {
			inode = entry.Inode.Identifier
		} else if entry.Inode.Identifier != inode {
			t.Errorf("%s has inode %d, want %d shared with the others", name, entry.Inode.Identifier, inode)
		}
		if got := entry.Inode.NumberOfLinks; got != uint32(len(names)) {
			t.Errorf("%s: nlink = %d, want %d", name, got, len(names))
		}

		content, err := vol.ReadFile(name)
		if err != nil {
			t.Errorf("ReadFile(%s): %v", name, err)
			continue
		}
		if !bytes.Equal(content, shared) {
			t.Errorf("%s: content = %q, want %q", name, content, shared)
		}
	}

	// A file outside the group must be its own inode with one link.
	plain, err := vol.FileEntryByPath("plain.txt")
	if err != nil {
		t.Fatalf("FileEntryByPath(plain.txt): %v", err)
	}
	if plain.Inode.Identifier == inode {
		t.Error("an unlinked file shares the linked inode")
	}
	if plain.Inode.NumberOfLinks != 1 {
		t.Errorf("plain.txt: nlink = %d, want 1", plain.Inode.NumberOfLinks)
	}
}

// TestCreateContainerHardLinksStoreContentOnce is the point of a hard link:
// the bytes exist once. Linking a large file many times must not grow the
// image the way copying it would.
func TestCreateContainerHardLinksStoreContentOnce(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 512*1024)

	linked := &apfswrite.Entry{}
	copies := &apfswrite.Entry{}
	for i, name := range []string{"a", "b", "c", "d", "e", "f"} {
		linked.Children = append(linked.Children, &apfswrite.Entry{Name: name, Data: payload, LinkGroup: 1})
		copies.Children = append(copies.Children, &apfswrite.Entry{Name: name, Data: payload, LinkGroup: uint64(i + 10)})
	}

	// Size the images to their contents, so the difference is visible: a fixed
	// size would make both come out the same length whatever they hold.
	autoSized := func(root *apfswrite.Entry) int {
		t.Helper()
		img := &memImage{}
		if err := apfswrite.CreateContainer(img, 0, &apfswrite.CreateOptions{VolumeName: "L", Root: root}); err != nil {
			t.Fatalf("CreateContainer: %v", err)
		}
		return len(img.data)
	}

	withLinks := autoSized(linked)
	withCopies := autoSized(copies)

	// Six copies of 512 KiB against one: the difference is unmistakable.
	if withLinks >= withCopies {
		t.Errorf("six links produced %d bytes and six copies %d; the content is being written per name",
			withLinks, withCopies)
	}
	t.Logf("six names for one 512 KiB file: %d bytes as links, %d as copies", withLinks, withCopies)
}

// TestCreateContainerSingleNameGroupHasNoSiblings checks a link group with only
// one name produces an ordinary file. A checker tolerates a lone sibling record
// but does not require one, and emitting it would change every existing image.
func TestCreateContainerSingleNameGroupHasNoSiblings(t *testing.T) {
	grouped := buildImage(t, &apfswrite.CreateOptions{
		VolumeName: "S",
		Root:       &apfswrite.Entry{Children: []*apfswrite.Entry{{Name: "only.txt", Data: []byte("x\n"), LinkGroup: 9}}},
	})
	plain := buildImage(t, &apfswrite.CreateOptions{
		VolumeName: "S",
		Root:       &apfswrite.Entry{Children: []*apfswrite.Entry{{Name: "only.txt", Data: []byte("x\n")}}},
	})
	if !bytes.Equal(grouped, plain) {
		t.Error("a link group with one name differs from an ungrouped file; it should produce no sibling records")
	}
}

// TestCreateContainerHardLinksAreDeterministic checks links do not disturb
// reproducibility: sibling ids are assigned from a walk whose order is fixed.
func TestCreateContainerHardLinksAreDeterministic(t *testing.T) {
	opts := func() *apfswrite.CreateOptions {
		return &apfswrite.CreateOptions{
			VolumeName: "D",
			Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
				{Name: "a", Data: []byte("one\n"), LinkGroup: 1},
				{Name: "b", Data: []byte("one\n"), LinkGroup: 1},
				{Name: "c", Data: []byte("two\n"), LinkGroup: 2},
				{Name: "d", Data: []byte("two\n"), LinkGroup: 2},
			}},
		}
	}
	first := buildImage(t, opts())
	for range 5 {
		if !bytes.Equal(first, buildImage(t, opts())) {
			t.Fatal("two builds with the same links differ")
		}
	}
}

// TestCreateContainerLinkGroupIgnoredOnDirectories checks a link group on
// something that cannot be linked is ignored rather than producing a broken
// image. Directories and symbolic links cannot be hard linked.
func TestCreateContainerLinkGroupIgnoredOnDirectories(t *testing.T) {
	vol := openVolume(t, &apfswrite.CreateOptions{
		VolumeName: "IGNORE",
		Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "d1", Mode: os.ModeDir, LinkGroup: 1},
			{Name: "d2", Mode: os.ModeDir, LinkGroup: 1},
			{Name: "l1", Mode: os.ModeSymlink, Data: []byte("d1"), LinkGroup: 2},
			{Name: "l2", Mode: os.ModeSymlink, Data: []byte("d1"), LinkGroup: 2},
		}},
	})

	for _, pair := range [][2]string{{"d1", "d2"}, {"l1", "l2"}} {
		a, err := vol.FileEntryByPath(pair[0])
		if err != nil {
			t.Fatalf("FileEntryByPath(%s): %v", pair[0], err)
		}
		b, err := vol.FileEntryByPath(pair[1])
		if err != nil {
			t.Fatalf("FileEntryByPath(%s): %v", pair[1], err)
		}
		if a.Inode.Identifier == b.Inode.Identifier {
			t.Errorf("%s and %s share an inode; only regular files can be linked", pair[0], pair[1])
		}
	}
}
