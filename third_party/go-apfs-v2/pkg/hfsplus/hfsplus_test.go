package hfsplus_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/fstest"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
)

// openVolume opens an HFS+ volume from a disk image via pkg/disk.
func openVolume(t *testing.T, imagePath string) *hfsplus.Volume {
	t.Helper()

	reader, offset, closer, err := disk.OpenWithOffset(imagePath)
	if err != nil {
		t.Fatalf("unable to open image %s: %v", imagePath, err)
	}
	t.Cleanup(func() { closer.Close() })

	var device io.ReaderAt = reader
	if offset != 0 {
		device = io.NewSectionReader(reader, offset, 1<<62)
	}

	volume, err := hfsplus.New(device)
	if err != nil {
		t.Fatalf("unable to parse HFS+ volume: %v", err)
	}

	return volume
}

// TestVolumeFS runs the io/fs conformance suite against a real HFS+ image.
// Gated on HFSPLUS_TEST_IMG so CI without an image skips it:
//
//	HFSPLUS_TEST_IMG=/path/to/image.dmg go test -run TestVolumeFS ./pkg/hfsplus
func TestVolumeFS(t *testing.T) {
	imagePath := os.Getenv("HFSPLUS_TEST_IMG")
	if imagePath == "" {
		t.Skip("HFSPLUS_TEST_IMG not set; skipping io/fs conformance test against a real image")
	}

	volume := openVolume(t, imagePath)

	// fstest.TestFS with no expected files asserts an empty file system, so
	// discover a few real paths to pass as expectations first
	var expected []string
	err := fs.WalkDir(volume, ".", func(name string, entry fs.DirEntry, err error) error {
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

// manifest mirrors testdata/cli/hfs-manifest.json.
type manifest struct {
	Files      map[string]manifestEntry `json:"files"`
	VolumeName string                   `json:"volumeName"`
}

type manifestEntry struct {
	Type   string `json:"type"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Target string `json:"target"`

	// Compressed marks a file stored with transparent compression. The size
	// and hash above are of its decompressed content, which is what a reader
	// must reproduce.
	Compressed bool `json:"compressed"`

	// Xattrs records the extended attributes macOS reported, by name. It is
	// not exhaustive: macOS hides com.apple.decmpfs and the resource fork of a
	// compressed file from a normal listing, so a volume may hold attributes
	// this map does not name. Assert containment, not equality.
	Xattrs map[string]manifestXattr `json:"xattrs"`
}

type manifestXattr struct {
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

// TestFixtureManifest verifies the committed hfs-basic.dmg fixture against
// its manifest: content hashes, sizes, permission bits and symlink targets.
// It runs unconditionally, locating the fixture relative to the package.
func TestFixtureManifest(t *testing.T) {
	imagePath := filepath.Join("..", "..", "testdata", "cli", "hfs-basic.dmg")
	manifestPath := filepath.Join("..", "..", "testdata", "cli", "hfs-manifest.json")

	if _, err := os.Stat(imagePath); err != nil {
		t.Fatalf("fixture image missing: %v", err)
	}

	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("unable to read manifest: %v", err)
	}
	var want manifest
	if err := json.Unmarshal(manifestData, &want); err != nil {
		t.Fatalf("unable to parse manifest: %v", err)
	}

	volume := openVolume(t, imagePath)

	if volume.Name() != want.VolumeName {
		t.Errorf("volume name = %q, want %q", volume.Name(), want.VolumeName)
	}

	var expected []string
	for name, entry := range want.Files {
		switch entry.Type {
		case "file":
			expected = append(expected, name)

			info, err := volume.Stat(name)
			if err != nil {
				t.Errorf("stat %s: %v", name, err)
				continue
			}
			if info.Size() != entry.Size {
				t.Errorf("%s: size = %d, want %d", name, info.Size(), entry.Size)
			}
			wantMode, err := strconv.ParseUint(entry.Mode, 0, 32)
			if err != nil {
				t.Fatalf("%s: bad mode in manifest: %v", name, err)
			}
			if got := uint64(info.Mode().Perm()); got != wantMode {
				t.Errorf("%s: mode = %#o, want %#o", name, got, wantMode)
			}

			data, err := volume.ReadFile(name)
			if err != nil {
				t.Errorf("readfile %s: %v", name, err)
				continue
			}
			sum := sha256.Sum256(data)
			if got := hex.EncodeToString(sum[:]); got != entry.SHA256 {
				t.Errorf("%s: sha256 = %s, want %s", name, got, entry.SHA256)
			}

		case "symlink":
			info, err := volume.Stat(name)
			if err != nil {
				t.Errorf("stat %s: %v", name, err)
				continue
			}
			if info.Mode()&fs.ModeSymlink == 0 {
				t.Errorf("%s: mode %v is not a symlink", name, info.Mode())
			}
			target, err := volume.Readlink(name)
			if err != nil {
				t.Errorf("readlink %s: %v", name, err)
				continue
			}
			if target != entry.Target {
				t.Errorf("%s: target = %q, want %q", name, target, entry.Target)
			}

		default:
			t.Fatalf("%s: unknown manifest entry type %q", name, entry.Type)
		}
	}

	if err := fstest.TestFS(volume, expected...); err != nil {
		t.Fatalf("fs.FS conformance failed: %v", err)
	}
}

// TestFixtureVolumeInfo sanity-checks the CLI-facing volume accessors on
// the committed fixture.
func TestFixtureVolumeInfo(t *testing.T) {
	volume := openVolume(t, filepath.Join("..", "..", "testdata", "cli", "hfs-basic.dmg"))

	if volume.FileCount() == 0 {
		t.Error("FileCount() = 0, want > 0")
	}
	if volume.FolderCount() == 0 {
		t.Error("FolderCount() = 0, want > 0")
	}
	if volume.CaseSensitive() {
		t.Error("CaseSensitive() = true for a plain HFS+ fixture")
	}
	if volume.Created().IsZero() || volume.Created().Year() < 2000 {
		t.Errorf("Created() = %v, want a modern timestamp", volume.Created())
	}
	if volume.Modified().IsZero() || volume.Modified().Year() < 2000 {
		t.Errorf("Modified() = %v, want a modern timestamp", volume.Modified())
	}
	if volume.UUID() == "" {
		t.Error("UUID() = \"\", want a volume identifier")
	}

	// Case-insensitive lookup must find files regardless of case.
	if _, err := volume.Stat("HELLO.TXT"); err != nil {
		t.Errorf("case-insensitive Stat(HELLO.TXT): %v", err)
	}

	// Reading with an empty buffer returns (0, nil).
	file, err := volume.Open("hello.txt")
	if err != nil {
		t.Fatalf("open hello.txt: %v", err)
	}
	defer file.Close()
	if n, err := file.Read(nil); n != 0 || err != nil {
		t.Errorf("empty Read = (%d, %v), want (0, nil)", n, err)
	}

	// Reads are clamped to file size, never padded past EOF.
	info, _ := file.Stat()
	big := make([]byte, info.Size()+100)
	n, err := file.Read(big)
	if int64(n) != info.Size() {
		t.Errorf("oversized Read returned %d bytes, want %d", n, info.Size())
	}
	if err != nil && err != io.EOF {
		t.Errorf("oversized Read error = %v, want nil or EOF", err)
	}

	// Hard links resolve to identical content.
	direct, err := volume.ReadFile("hello.txt")
	if err != nil {
		t.Fatalf("readfile hello.txt: %v", err)
	}
	linked, err := volume.ReadFile("hardlink-to-hello")
	if err != nil {
		t.Fatalf("readfile hardlink-to-hello: %v", err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(direct)) != fmt.Sprintf("%x", sha256.Sum256(linked)) {
		t.Error("hard link content differs from its target")
	}
}
