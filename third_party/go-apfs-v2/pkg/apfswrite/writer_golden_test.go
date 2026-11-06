// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// goldenTree is a small but representative volume: files at the root and in a
// nested directory, an empty file, and a symbolic link. It exercises inode
// numbering, the file-system tree, extents and the object map without being
// large enough to make the hash fragile for uninteresting reasons.
func goldenTree() *apfswrite.Entry {
	return &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "a.txt", Data: []byte("alpha\n")},
		{Name: "empty.txt"},
		{Name: "link", Mode: fs.ModeSymlink, Data: []byte("a.txt")},
		{Name: "dir", Mode: fs.ModeDir, Children: []*apfswrite.Entry{
			{Name: "b.txt", Data: []byte("beta\n")},
		}},
	}}
}

// goldenImage builds the reference container. Everything about it is fixed --
// the timestamps and UUIDs default to constants -- so the bytes are a function
// of the writer alone.
func goldenImage(t *testing.T) []byte {
	t.Helper()
	img := &memImage{}
	err := apfswrite.CreateContainer(img, 64*1024*1024, &apfswrite.CreateOptions{
		VolumeName: "GOLDEN",
		Root:       goldenTree(),
	})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	return img.data
}

// goldenSHA256 is the checksum of that container.
//
// It exists to make a refactor prove itself. Rearranging how the writer is
// structured -- pulling the per-volume state out of the builder so a second
// volume can exist, most of all -- must not change the bytes a single-volume
// container is made of. A diff in this hash means the refactor changed
// behaviour, which is exactly what it must not do.
//
// Update it only alongside a deliberate change to the format the writer emits,
// and say in the commit message what moved and why.
const goldenSHA256 = "6c1f9df04bf699935fdad64c8d562d1123eaad9ed25ef566abc6095c360915c7"

func TestGoldenSingleVolumeImage(t *testing.T) {
	sum := sha256.Sum256(goldenImage(t))
	got := hex.EncodeToString(sum[:])
	if got != goldenSHA256 {
		t.Errorf("the single-volume container changed:\n  got  %s\n  want %s\n"+
			"If this was deliberate, update goldenSHA256 and say what moved.", got, goldenSHA256)
	}
}

// TestGoldenImageIsDeterministic guards the property the hash depends on: the
// same input must produce the same bytes, or the hash above would be noise.
func TestGoldenImageIsDeterministic(t *testing.T) {
	first, second := goldenImage(t), goldenImage(t)
	if len(first) != len(second) {
		t.Fatalf("two runs produced %d and %d bytes", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("two runs differ at byte %d", i)
		}
	}
}
