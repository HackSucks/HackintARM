// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// File content is written in fixed windows rather than one buffer per file, so
// a single large file no longer costs its own size in memory. The boundaries
// are where an off-by-one would hide: a file exactly one window long, one byte
// either side of it, and one spanning several windows with a partial tail.
func TestFileDataWindowBoundaries(t *testing.T) {
	const blockSize = 4096
	const window = 1024 * blockSize // must match fileCopyWindowBlocks

	sizes := []int{
		1,
		blockSize - 1,
		blockSize,
		blockSize + 1,
		window - 1,
		window,
		window + 1,
		2*window + 12345,
	}

	root := &apfswrite.Entry{}
	want := map[string][2]any{}
	for i, size := range sizes {
		name := fmt.Sprintf("f%02d-%d.bin", i, size)
		data := make([]byte, size)
		rand.New(rand.NewSource(int64(size))).Read(data)
		root.Children = append(root.Children, &apfswrite.Entry{Name: name, Data: data})
		want[name] = [2]any{size, sha256.Sum256(data)}
	}

	vol := openVolume(t, &apfswrite.CreateOptions{VolumeName: "WINDOW", Root: root})

	for name, expected := range want {
		got, err := vol.ReadFile(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(got) != expected[0].(int) {
			t.Errorf("%s: read %d bytes, want %d", name, len(got), expected[0])
			continue
		}
		if sha256.Sum256(got) != expected[1].([32]byte) {
			t.Errorf("%s: content differs after a windowed write", name)
		}
	}
}

// TestFileDataTailIsZeroPadded checks the last block of a file is zero-padded
// rather than carrying whatever the reused window held from the file before.
func TestFileDataTailIsZeroPadded(t *testing.T) {
	const blockSize = 4096

	// A large file of 0xff first, then a small one, so the reused window is
	// full of 0xff when the small file's partial tail is written.
	big := bytes.Repeat([]byte{0xff}, 3*blockSize)
	small := []byte("small\n")

	vol := openVolume(t, &apfswrite.CreateOptions{
		VolumeName: "PADDING",
		Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "a-big.bin", Data: big},
			{Name: "b-small.txt", Data: small},
		}},
	})

	got, err := vol.ReadFile("b-small.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, small) {
		t.Errorf("read %q, want %q; the reused window leaked into the tail", got, small)
	}
}
