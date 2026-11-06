// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// TestCreateContainerWithFile formats a container holding one root-level
// regular file, reads it back with the MIT reader, and asserts the file lists
// with the right name and that its content's sha256 matches. This is the
// cross-platform correctness gate (runs on every OS).
func TestCreateContainerWithFile(t *testing.T) {
	content := []byte("Hello, APFS milestone 1!\nThis is a single-extent regular file.\n")
	want := sha256.Sum256(content)

	const size = 32 * 1024 * 1024
	img := &memImage{}
	opts := &apfswrite.CreateOptions{
		VolumeName: "FileVol",
		RootFiles:  []apfswrite.RootFile{{Name: "hello.txt", Data: content}},
	}
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
	v := volumes[0]

	// The root directory lists exactly the one file.
	entries, err := v.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("root has %d entries %v, want 1 (hello.txt)", len(entries), names)
	}
	if got := entries[0].Name(); got != "hello.txt" {
		t.Errorf("entry name = %q, want %q", got, "hello.txt")
	}
	if entries[0].IsDir() {
		t.Errorf("entry reported as directory, want regular file")
	}

	// Size matches the content length.
	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Size() != int64(len(content)) {
		t.Errorf("size = %d, want %d", info.Size(), len(content))
	}

	// Content round-trips exactly (sha256).
	got, err := v.ReadFile("hello.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(content))
	}
	if gotHash := sha256.Sum256(got); gotHash != want {
		t.Errorf("sha256 = %x, want %x", gotHash, want)
	}
}

// TestCreateContainerWithFileEmptyStillWorks confirms the no-files path is
// unchanged: a container built without RootFiles has an empty root.
func TestCreateContainerWithFileEmptyStillWorks(t *testing.T) {
	const size = 8 * 1024 * 1024
	img := &memImage{}
	if err := apfswrite.CreateContainer(img, size, &apfswrite.CreateOptions{VolumeName: "Empty"}); err != nil {
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
	entries, err := volumes[0].ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("empty container root has %d entries, want 0", len(entries))
	}
}

// TestCreateContainerWithFileRejectsUnsupported checks the remaining input
// guards. As of milestone 3, over-a-block content and empty files are both
// supported; a name with a path separator is still rejected.
func TestCreateContainerWithFileRejectsUnsupported(t *testing.T) {
	const size = 8 * 1024 * 1024

	t.Run("bad-name", func(t *testing.T) {
		img := &memImage{}
		err := apfswrite.CreateContainer(img, size, &apfswrite.CreateOptions{
			RootFiles: []apfswrite.RootFile{{Name: "a/b", Data: []byte("x")}},
		})
		if err == nil {
			t.Fatal("expected error for a name containing a path separator")
		}
	})

	t.Run("multi-block-now-ok", func(t *testing.T) {
		img := &memImage{}
		big := bytes.Repeat([]byte{'x'}, 4096+1)
		if err := apfswrite.CreateContainer(img, size, &apfswrite.CreateOptions{
			RootFiles: []apfswrite.RootFile{{Name: "big", Data: big}},
		}); err != nil {
			t.Fatalf("multi-block file should now be supported: %v", err)
		}
	})

	t.Run("empty-file-now-ok", func(t *testing.T) {
		img := &memImage{}
		if err := apfswrite.CreateContainer(img, size, &apfswrite.CreateOptions{
			RootFiles: []apfswrite.RootFile{{Name: "empty", Data: nil}},
		}); err != nil {
			t.Fatalf("empty file should now be supported: %v", err)
		}
	})
}
