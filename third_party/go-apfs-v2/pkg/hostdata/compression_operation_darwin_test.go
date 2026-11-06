package hostdata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"golang.org/x/sys/unix"
)

func TestRecompressNativeFiles(t *testing.T) {
	base := os.Getenv("APFS_COMPRESSION_MOUNT")
	if base == "" {
		base = t.TempDir()
	}
	probe, e := os.CreateTemp(base, "operation-volume-")
	if e != nil {
		t.Fatal(e)
	}
	volume, e := CompressionVolumeFlags(t.Context(), probe)
	if e != nil {
		t.Fatal(e)
	}
	if e = errors.Join(probe.Close(), os.Remove(probe.Name())); e != nil {
		t.Fatal(e)
	}
	var mounted unix.Statfs_t
	if e = unix.Statfs(base, &mounted); e != nil {
		t.Fatal(e)
	}
	filesystem := unix.ByteSliceToString(mounted.Fstypename[:])
	version, e := osversion.Detect(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	profile, e := osversion.ProfileForMacOS(version)
	if e != nil {
		t.Fatal(e)
	}
	fixture := map[osversion.MacOSProfile]string{osversion.MacOS15: "compression-operation-macos15", osversion.MacOS26: "compression-operation-macos26", osversion.MacOS27: "compression-operation"}[profile]
	if fixture == "" {
		t.Fatal("unqualified native compression OS profile", version)
	}
	cases := map[string]compressionLifecycleTrial{}
	trials := compressionTrials(t, fixture, 330)
	// The hosted runner and developer APFS volumes have different content-
	// protection flags. Keep native byte/metadata qualification for both;
	// physical allocation comparison remains a separate unresolved oracle gate.
	if profile == osversion.MacOS27 {
		trials = append(trials, compressionTrials(t, "allocation-observations/macos27-first", 330)...)
	}
	for _, c := range trials {

		if c.Fault != "" || c.Scenario != "ordinary" && c.Scenario != "multi-block" || c.Observation.VolumeFlags&0x80 != volume&0x80 || c.Observation.FilesystemType != filesystem {
			continue
		}
		cases[c.Scenario+"/"+c.Requested+"/"+c.Inline] = c
	}
	if len(cases) != 22 {
		t.Fatal("unqualified native operation inventory/mount policy", len(cases), volume)
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, e := os.CreateTemp(base, "recompress-")
			if e != nil {
				t.Fatal(e)
			}
			path := f.Name()
			defer os.Remove(path)
			if _, e = f.Write(c.Data); e != nil {
				t.Fatal(e)
			}
			// Retain a read descriptor while the fixture is still uncompressed.
			// Later inspection must not reopen it and alter access time.
			observer, e := os.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer observer.Close()
			metadata, e := NewHeldMetadata(f)
			if e != nil {
				t.Fatal(e)
			}
			if e = metadata.SetTimes(time.Unix(1600000000, 987654321), time.Unix(1550000000, 345678901)); e != nil {
				t.Fatal(e)
			}
			source, e := metadata.CaptureStat()
			if e != nil {
				t.Fatal(e)
			}
			before, e := f.Stat()
			if e != nil {
				t.Fatal(e)
			}
			if e = f.Close(); e != nil {
				t.Fatal(e)
			}
			h := newRecompressionHarness(t, nil)
			options := h.options
			options.Name = filepath.Base(path)
			if c.Requested != "default" {
				kind, e := strconv.ParseUint(c.Requested, 10, 32)
				if e != nil {
					t.Fatal(e)
				}
				options.Encoding.Type = uint32(kind)
			}
			options.Encoding.ResourceForkOnly = c.Inline == "no"
			result, e := Recompress(t.Context(), func(ctx context.Context) (CompressionInput, error) { return OpenNativeCompressionInput(ctx, path) }, options)
			if e != nil || !result.Accepted || !result.Installation.Commit.Activated || !result.Installation.Commit.Completed || len(result.Installation.Commit.Failures) != 0 {
				t.Fatal(result, e)
			}
			var pathState unix.Stat_t
			if e = unix.Stat(path, &pathState); e != nil {
				t.Fatal(e)
			}

			f = observer
			var held unix.Stat_t
			if e = withXattrDescriptor(f, func(fd int) error { return unix.Fstat(fd, &held) }); e != nil {
				t.Fatal(e)
			}
			if held.Dev != pathState.Dev || held.Ino != pathState.Ino || held.Nlink != pathState.Nlink || held.Size != pathState.Size {
				t.Fatal("held/path identity, link count or size differs", held, pathState)
			}
			after, e := f.Stat()
			if e != nil || !os.SameFile(before, after) {
				t.Fatal("inode changed", e)
			}
			metadata, e = NewHeldMetadata(f)
			if e != nil {
				t.Fatal(e)
			}
			state := heldStatMetadata(pathState)
			observed, e := metadata.CaptureStat()
			if e != nil {
				t.Fatal(e)
			}
			expectedObservation := c.Observation.ObserverHeldMetadataUnchanged
			if expectedObservation == nil || !*expectedObservation || observed != state {
				t.Fatal("held metadata observation differs", expectedObservation, state, observed)
			}

			if state.Flags != UFCompressed || state.Mode != source.Mode || !state.Times.Modify.Equal(source.Times.Modify.Truncate(time.Microsecond)) || !state.Times.Access.Equal(source.Times.Access.Truncate(time.Microsecond)) {
				t.Fatal("native restoration", source, state, e)
			}
			for _, v := range []struct {
				name string
				want []byte
			}{{DecmpfsName, c.Attribute}, {ResourceForkName, c.Fork}} {
				var got []byte
				e = withXattrDescriptor(f, func(fd int) error {
					var err error
					got, _, err = readVisibleXattr(func(p []byte) (int, error) { return getCaptureXattrFD(fd, v.name, p) }, 1<<20)
					return err
				})
				if e != nil || !bytes.Equal(got, v.want) {
					t.Fatal("native storage differs", v.name, len(got), len(v.want), e)
				}
			}
			got, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(got, c.Data) {
				t.Fatal("native kernel readback differs", e)
			}
			h.cleanupCheck()
		})
	}
}

func TestNativeCompressionAcquisitionErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := OpenNativeCompressionInput(ctx, "unused"); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := OpenNativeCompressionInput(t.Context(), filepath.Join(t.TempDir(), "missing")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
	for _, closed := range []bool{false, true} {
		t.Run(fmt.Sprint(closed), func(t *testing.T) {
			// A test-owned impossible descriptor exercises kernel errors without closing
			// or reusing a real descriptor behind os.File's lifetime management.
			f := os.NewFile(1<<28, "invalid-test-descriptor")
			if f == nil {
				t.Fatal("descriptor wrapper")
			}
			if closed {
				_ = f.Close()
			} else {
				defer f.Close()
			}
			input := nativeCompressionInput{file: f, ctx: t.Context()}
			if _, e := input.Snapshot(); e == nil {
				t.Fatal("invalid stat accepted")
			}
			if e := input.ProbeWrite(); e == nil {
				t.Fatal("invalid zero-byte write accepted")
			}
			if _, e := input.Duplicate(); e == nil {
				t.Fatal("invalid duplicate accepted")
			}
			stream := nativeCompressionStream{heldCompressionCommit: &heldCompressionCommit{file: f}, ctx: t.Context()}
			if _, e := stream.OpenCompressionFork(); e == nil {
				t.Fatal("invalid fork open accepted")
			}
			if _, e := stream.VolumeFlags(); e == nil {
				t.Fatal("invalid volume accepted")
			}
			if _, e := stream.ReadAt(make([]byte, 1), 0); e == nil {
				t.Fatal("invalid read accepted")
			}
		})
	}
}

func TestNativeCompressionAcquisitionDecompresses(t *testing.T) {
	h := newRecompressionHarness(t, bytes.Repeat([]byte("abcd"), 16384))
	path := filepath.Join(h.dir, "data")
	h.options.Name = "data"
	open := func(ctx context.Context) (CompressionInput, error) { return OpenNativeCompressionInput(ctx, path) }
	result, e := Recompress(t.Context(), open, h.options)
	if e != nil || !result.Installation.Commit.Activated {
		t.Fatal(result, e)
	}
	input, e := OpenNativeCompressionInput(t.Context(), path)
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	state, e := input.Snapshot()
	if e != nil || state.Stat.Flags&UFCompressed != 0 || state.Size != int64(len(h.plain)) {
		t.Fatal("read/write acquisition did not materialize data", state, e)
	}
	if e = input.ProbeWrite(); e != nil {
		t.Fatal(e)
	}
	stream, e := input.Duplicate()
	if e != nil {
		t.Fatal(e)
	}
	defer stream.Close()
	got := make([]byte, len(h.plain))
	n, e := stream.ReadAt(got, 0)
	if e != nil || n != len(got) || !bytes.Equal(got, h.plain) {
		t.Fatal("duplicated held data differs", n, e)
	}
	file, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	e = withXattrDescriptor(file, func(fd int) error {
		_, e := getCaptureXattrFD(fd, DecmpfsName, nil)
		if !errors.Is(e, unix.ENOATTR) {
			return fmt.Errorf("compression attribute remained: %w", e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
