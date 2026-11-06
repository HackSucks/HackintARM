package apfs

import (
	"io/fs"
	"os"
	"testing"
	"testing/fstest"
)

// TestVolumeFS runs the io/fs conformance suite against the first volume of
// a real APFS image. Gated on APFS_BIG_DMG so CI without an image skips it:
//
//	APFS_BIG_DMG=/path/to/image.dmg go test -run TestVolumeFS ./pkg/apfs
func TestVolumeFS(t *testing.T) {
	imagePath := os.Getenv("APFS_BIG_DMG")
	if imagePath == "" {
		t.Skip("APFS_BIG_DMG not set; skipping io/fs conformance test against a real image")
	}

	container, closer, err := OpenImage(imagePath, nil)
	if err != nil {
		t.Fatalf("unable to open image: %v", err)
	}
	defer closer.Close()
	defer container.Close()

	volumes, err := container.Volumes()
	if err != nil {
		t.Fatalf("unable to enumerate volumes: %v", err)
	}
	if len(volumes) == 0 {
		t.Fatal("image contains no volumes")
	}

	volume := volumes[0]

	// fstest.TestFS with no expected files asserts an empty file system, so
	// discover a few real paths to pass as expectations first
	var expected []string
	err = fs.WalkDir(volume, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() && len(expected) < 5 {
			expected = append(expected, name)
		}
		if len(expected) >= 5 {
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unable to discover files for expectations: %v", err)
	}
	if len(expected) == 0 {
		t.Fatal("volume contains no regular files to test against")
	}

	if err := fstest.TestFS(volume, expected...); err != nil {
		t.Fatalf("fs.FS conformance failed: %v", err)
	}
}
