// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// memImage is a growable in-memory io.WriterAt / io.ReaderAt used to build and
// then read back a container without touching the file system.
type memImage struct {
	data []byte
}

func (m *memImage) WriteAt(p []byte, off int64) (int, error) {
	end := off + int64(len(p))
	if end > int64(cap(m.data)) {
		// Grow geometrically: the writer appends block by block, and growing
		// to exactly the new end would copy the whole image on every write.
		// make, not append, so the pages past what is copied stay untouched:
		// the writer sizes a container by writing its last byte, and clearing
		// a gigabyte container's pages made them resident (5.9 GB under -race).
		grown := make([]byte, end, max(end, 2*int64(cap(m.data))))
		copy(grown, m.data)
		m.data = grown
	} else if end > int64(len(m.data)) {
		m.data = m.data[:end]
	}
	copy(m.data[off:], p)
	return len(p), nil
}

func (m *memImage) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, fmt.Errorf("read past end of image")
	}
	n := copy(p, m.data[off:])
	return n, nil
}

// TestCreateContainerReadRoundTrip formats a container in memory and reads it
// back with the MIT reader. It runs on every OS and is the cross-platform gate.
func TestCreateContainerReadRoundTrip(t *testing.T) {
	containerUUID := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x47, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	volumeUUID := [16]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x47, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	cases := []struct {
		name          string
		caseSensitive bool
	}{
		{"case-insensitive", false},
		{"case-sensitive", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const size = 8 * 1024 * 1024
			img := &memImage{}
			opts := &apfswrite.CreateOptions{
				VolumeName:    "RoundTrip",
				CaseSensitive: tc.caseSensitive,
				ContainerUUID: containerUUID,
				VolumeUUID:    volumeUUID,
			}
			if err := apfswrite.CreateContainer(img, size, opts); err != nil {
				t.Fatalf("CreateContainer: %v", err)
			}

			container, err := apfs.Open(img, &apfs.OpenOptions{})
			if err != nil {
				t.Fatalf("apfs.Open: %v", err)
			}

			// Container UUID.
			gotCUUID, err := container.Identifier()
			if err != nil {
				t.Fatalf("container GetIdentifier: %v", err)
			}
			if !bytesEqual(gotCUUID, containerUUID[:]) {
				t.Errorf("container UUID = %x, want %x", gotCUUID, containerUUID)
			}

			// Exactly one volume.
			volumes, err := container.Volumes()
			if err != nil {
				t.Fatalf("Volumes: %v", err)
			}
			if len(volumes) != 1 {
				t.Fatalf("volume count = %d, want 1", len(volumes))
			}
			v := volumes[0]

			// Name.
			name, err := v.UTF8Name()
			if err != nil {
				t.Fatalf("GetUTF8Name: %v", err)
			}
			if name != "RoundTrip" {
				t.Errorf("volume name = %q, want %q", name, "RoundTrip")
			}

			// Volume UUID.
			gotVUUID, err := v.Identifier()
			if err != nil {
				t.Fatalf("volume GetIdentifier: %v", err)
			}
			if gotVUUID != volumeUUID {
				t.Errorf("volume UUID = %x, want %x", gotVUUID, volumeUUID)
			}

			// Case sensitivity.
			caseInsensitive, err := v.IsCaseInsensitive()
			if err != nil {
				t.Fatalf("IsCaseInsensitive: %v", err)
			}
			if caseInsensitive != !tc.caseSensitive {
				t.Errorf("IsCaseInsensitive = %v, want %v", caseInsensitive, !tc.caseSensitive)
			}

			// Zero user files: the root directory is empty.
			entries, err := v.ReadDir(".")
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			if len(entries) != 0 {
				names := make([]string, len(entries))
				for i, e := range entries {
					names[i] = e.Name()
				}
				t.Errorf("root has %d entries %v, want 0", len(entries), names)
			}
		})
	}
}

// TestCreateContainerBlockSize pins the one block size this writer emits.
//
// The format permits any power of two from 4096 to 65536, and the writer's
// arithmetic is parameterised by block size throughout, so the larger sizes
// used to be accepted. What came out was not sound: at 16384 both fsck_apfs
// ("invalid btn_table_space", no valid checkpoint) and apfsck ("Omap record:
// bad alignment for key or value") reject the container, and at 65536
// fsck_apfs spins without reaching a verdict. All of them are also unreadable
// by pkg/apfs, whose superblock checksum spans a fixed 4096 bytes.
//
// If this writer ever lays out larger blocks correctly, this test is the thing
// to change -- deliberately, with a checker's verdict behind it.
func TestCreateContainerBlockSize(t *testing.T) {
	for _, tc := range []struct {
		blockSize uint32
		wantOK    bool
	}{
		{0, true}, // zero means "default"
		{4096, true},
		{8192, false},
		{16384, false},
		{65536, false},
		{1024, false},   // below the format minimum
		{131072, false}, // above the format maximum
		{6000, false},   // not a power of two
	} {
		img := &memImage{}
		err := apfswrite.CreateContainer(img, 32<<20, &apfswrite.CreateOptions{
			BlockSize:  tc.blockSize,
			VolumeName: "blocksize",
		})
		switch {
		case tc.wantOK && err != nil:
			t.Errorf("block size %d: CreateContainer failed: %v", tc.blockSize, err)
		case !tc.wantOK && err == nil:
			t.Errorf("block size %d: CreateContainer succeeded, want refusal", tc.blockSize)
		case !tc.wantOK && !strings.Contains(err.Error(), "unsupported block size"):
			t.Errorf("block size %d: error %q does not say the block size is unsupported",
				tc.blockSize, err)
		}
	}
}

func bytesEqual(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- darwin test helpers ---
