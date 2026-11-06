// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"fmt"
	"testing"
)

// TestVarTreeLevelsClose checks that records of every size pack into levels
// that each fit a block, that every index level is narrower than the one below
// it, and that the tree closes into a single root.
func TestVarTreeLevelsClose(t *testing.T) {
	const bs = 4096
	for _, tc := range []struct {
		name     string
		n        int
		key, val int
	}{
		{"one record", 1, 16, 16},
		{"extentref records", 200_000, sizeofPhysExtKey, sizeofPhysExtVal},
		{"short directory entries", 100_000, 24, 18},
		{"long directory entries", 20_000, 12 + 255, 18},
		{"inline attributes", 2_000, 40, 3000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recs := make([]fsTreeRecord, tc.n)
			for i := range recs {
				recs[i] = fsTreeRecord{key: make([]byte, tc.key), val: make([]byte, tc.val)}
			}
			levels, err := varTreeLevels(recs, bs)
			if err != nil {
				t.Fatal(err)
			}
			if root := levels[len(levels)-1]; len(root) != 1 {
				t.Fatalf("top level has %d nodes, want the root alone", len(root))
			}
			for li, level := range levels {
				footer := 0
				if li == len(levels)-1 {
					footer = sizeofBtreeInfo
				}
				for ni, node := range level {
					if need := varNodeBytes(node, footer); need > bs {
						t.Fatalf("level %d node %d needs %d bytes", li, ni, need)
					}
				}
				if li > 0 && len(level) >= len(levels[li-1]) {
					t.Fatalf("level %d has %d nodes, not fewer than the %d below it", li, len(level), len(levels[li-1]))
				}
			}
			t.Logf("%d records: %d levels, %d nodes", tc.n, len(levels), treeNodeCount(levels))
		})
	}
}

// TestOmapLevelSizes checks the object map grows a level each time the one
// below outgrows a root, and that the root-leaf still holds what it always
// has: 111 mappings.
func TestOmapLevelSizes(t *testing.T) {
	b := &builder{blocksize: 4096}
	if got := b.omapLevelSizes(111); len(got) != 1 {
		t.Fatalf("111 mappings: levels %v, want a single root-leaf", got)
	}
	for _, n := range []int{112, 10_000, 1_000_000} {
		sizes := b.omapLevelSizes(n)
		if sizes[len(sizes)-1] != 1 {
			t.Fatalf("%d mappings: levels %v do not close into a root", n, sizes)
		}
		t.Logf("%d mappings: nodes per level %v", n, sizes)
	}
	if got := len(b.omapLevelSizes(1_000_000)); got < 3 {
		t.Fatalf("a million mappings fit in %d levels; the test no longer reaches a third", got)
	}
}

// TestLargeTreesHaveSoundNodes writes a volume whose file-system and extentref
// trees are three levels tall and whose object map is two, and checks every
// node of every tree with checkNodeLayouts.
func TestLargeTreesHaveSoundNodes(t *testing.T) {
	if testing.Short() {
		t.Skip("writes tens of thousands of files")
	}
	root := &Entry{}
	for i := range 20_000 {
		root.Children = append(root.Children, &Entry{Name: fmt.Sprintf("f%07d", i), Data: []byte{byte(i)}})
	}
	var img memWriter
	if err := CreateContainer(&img, 0, &CreateOptions{VolumeName: "Big", Root: root}); err != nil {
		t.Fatal(err)
	}
	nodes, err := checkNodeLayouts(img.b)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d nodes checked", nodes)
}

// memWriter is an in-memory io.WriterAt.
type memWriter struct{ b []byte }

func (m *memWriter) WriteAt(p []byte, off int64) (int, error) {
	if end := int(off) + len(p); end > cap(m.b) {
		grown := make([]byte, end, max(end, 2*cap(m.b)))
		copy(grown, m.b)
		m.b = grown
	} else if end > len(m.b) {
		m.b = m.b[:end]
	}
	copy(m.b[off:], p)
	return len(p), nil
}
