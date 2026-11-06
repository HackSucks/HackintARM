package hostdata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/diskimage"
)

func TestReplacementVolumeCapabilityFailures(t *testing.T) {
	for _, tc := range []struct {
		length, value, valid uint32
		supported, failure   bool
	}{
		{36, 0x400, 0x400, true, false}, {36, 0, 0x400, false, false},
		{36, 0x400, 0, false, true}, {0, 0x400, 0x400, false, true},
	} {
		supported, err := replacementVolumeACLResult(tc.length, tc.value, tc.valid)
		if supported != tc.supported || (err != nil) != tc.failure || err != nil && !errors.Is(err, ErrUnsupportedReplacement) {
			t.Fatal(tc, supported, err)
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if supported, err := replacementVolumeACL(f); supported || err == nil {
		t.Fatal(supported, err)
	}
	if err := clearReplacementHeldACL(f); err == nil {
		t.Fatal(err)
	}
	if err := clearReplacementACL(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestReplacementVolumeDarwinNative(t *testing.T) {
	oracle := os.Getenv("APFS_REPLACEMENT_VOLUME_ORACLE")
	if oracle == "" {
		oracle = filepath.Join(t.TempDir(), "oracle")
		if out, err := cirunner.Command("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "../../testdata/appledouble/native/replacement-volume.c", "-o", oracle).CombinedOutput(); err != nil {
			t.Fatalf("compile volume oracle: %v %s", err, out)
		}
	}
	for _, filesystem := range []string{"APFS", "HFS+", "MS-DOS FAT32", "ExFAT"} {
		t.Run(filesystem, func(t *testing.T) {
			mount := replacementTestVolume(t, filesystem)
			replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
				source, err := os.CreateTemp(mount, "source")
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				if _, err := source.Write([]byte("original")); err != nil {
					t.Fatal(err)
				}
				if err := SetXattr(source, "com.example.retained", []byte("retained")); err != nil {
					t.Fatal(err)
				}
				native, err := cirunner.Command(oracle, source.Name(), source.Name()+".native").Output()
				if err != nil {
					t.Fatal(err)
				}
				var observation struct {
					BirthSeconds                int64 `json:"birth_seconds"`
					BirthNanoseconds            int64 `json:"birth_nanoseconds"`
					Status, Errno               int
					Length, Capabilities, Valid uint32
				}
				if err := json.Unmarshal(native, &observation); err != nil {
					t.Fatal(err)
				}
				expected := filesystem == "APFS" || filesystem == "HFS+"
				if observation.Status != 0 || observation.Errno != 0 || observation.Length != 36 || observation.Valid&0x400 == 0 || (observation.Capabilities&0x400 != 0) != expected {
					t.Fatalf("native capability changed: %s", native)
				}
				supported, err := replacementVolumeACL(source)
				if err != nil || supported != expected {
					t.Fatal(supported, err)
				}
				xattrFiles, err := FilesystemUsesXattrFiles(t.Context(), source)
				nativeXattrFiles := observation.Valid&0x4000 == 0 || observation.Capabilities&0x4000 == 0
				if err != nil || xattrFiles != nativeXattrFiles || xattrFiles == expected {
					t.Fatalf("xattr storage=%v native=%v filesystem=%s: %v", xattrFiles, nativeXattrFiles, filesystem, err)
				}
				before := replacementSnapshotOf(t, source)
				target, err := prepare(source, mount)
				if err != nil {
					t.Fatal(err)
				}
				defer target.Close()
				if _, err := target.File.WriteAt([]byte("replacement"), 0); err != nil {
					t.Fatal(err)
				}
				if err := target.File.Truncate(11); err != nil {
					t.Fatal(err)
				}
				if err := target.RestoreMetadata(); err != nil {
					t.Fatal(err)
				}
				value, present, err := ReadXattr(target.File, "com.example.retained", 100)
				if err != nil || !present || string(value) != "retained" {
					t.Fatal(value, present, err)
				}
				after := replacementSnapshotOf(t, target.File)
				if before.Mode != after.Mode || before.UID != after.UID || before.GID != after.GID || before.Flags != after.Flags || after.Birth.Sec != observation.BirthSeconds || after.Birth.Nsec != observation.BirthNanoseconds {
					t.Fatalf("metadata changed: %+v -> %+v", before, after)
				}
				stage := filepath.Dir(target.File.Name())
				if err := target.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(stage); !os.IsNotExist(err) {
					t.Fatalf("stage retained: %s %v", stage, err)
				}
				data, err := os.ReadFile(source.Name())
				if err != nil || !bytes.Equal(data, []byte("original")) {
					t.Fatal("source changed", err)
				}
				t.Logf("REPLACEMENT_VOLUME_NATIVE filesystem=%q capability=%s metadata_preserved=true source_unchanged=true stage_removed=true", filesystem, native)
			})
		})
	}
}

func replacementTestVolume(t *testing.T, filesystem string) string {
	t.Helper()
	work := t.TempDir()
	image, mount := filepath.Join(work, "volume.dmg"), filepath.Join(work, "mount")
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		data, err := cirunner.Command("hdiutil", args...).CombinedOutput()
		t.Logf("hdiutil %q: %s error=%v", args, data, err)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	run("create", "-size", "128m", "-fs", filesystem, "-volname", "METADATA", image)
	// Match capture-metadata-filesystem.go: FAT has no stored Unix owners.
	// Forcing ownership ties fixture access to the headless mount service.
	owners := "on"
	if filesystem == "MS-DOS FAT32" || filesystem == "ExFAT" {
		owners = "off"
	}
	attached := run("attach", "-plist", "-nobrowse", "-owners", owners, "-mountpoint", mount, image)
	device := mount
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		err := diskimage.RetryDetach(ctx, func() (int, error) {
			data, err := cirunner.CommandContext(ctx, "hdiutil", "detach", device).CombinedOutput()
			t.Logf("detach %s: %s error=%v", device, data, err)
			if err == nil {
				return 0, nil
			}
			var status *exec.ExitError
			if errors.As(err, &status) {
				return status.ExitCode(), err
			}
			return -1, err
		})
		if err != nil {
			t.Error(err)
		}
	})
	backing, err := diskimage.AttachmentDevice(attached)
	if err != nil {
		t.Fatal(err)
	}
	device = backing
	return mount
}
