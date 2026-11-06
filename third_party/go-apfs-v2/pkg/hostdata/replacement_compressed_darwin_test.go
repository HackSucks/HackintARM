package hostdata

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestReplacementCompressedDarwinNative(t *testing.T) {
	base := os.Getenv("APFS_REPLACEMENT_MOUNT")
	if base == "" {
		base = t.TempDir()
	}
	tools := t.TempDir()
	run := func(args ...string) []byte {
		t.Helper()
		out, err := cirunner.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	producer, oracle := filepath.Join(tools, "producer"), filepath.Join(tools, "oracle")
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-framework", "CoreFoundation", "../../testdata/appledouble/native/decmpfs-formats.c", "-o", producer)
	run("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "../../testdata/appledouble/native/replacement-compressed.c", "-o", oracle)
	cases := replacementCompressionSamples(t)
	// In addition to retained kernel-qualified containers, produce independent
	// zlib, LZVN and LZFSE files afresh on this host.
	for _, kind := range []uint32{3, 7, 11} {
		path := filepath.Join(tools, fmt.Sprintf("produce-%d", kind))
		plain := bytes.Repeat([]byte("native compressed replacement control "), 4096)
		if err := os.WriteFile(path, plain, 0600); err != nil {
			t.Fatal(err)
		}
		run(producer, "produce", fmt.Sprint(kind), path, path)
		attr, err := os.ReadFile(path + ".attr")
		if err != nil {
			t.Fatal(err)
		}
		fork, err := os.ReadFile(path + ".fork")
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		readback, err := os.ReadFile(path + ".readback")
		if err != nil || !bytes.Equal(readback, plain) {
			t.Fatal("native producer readback", err)
		}
		cases = append(cases, replacementCompressionSample{fmt.Sprintf("producer-%d", kind), binary.LittleEndian.Uint32(attr[4:]), plain, attr, fork})
	}
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		for _, tc := range cases {
			t.Run(tc.Name, func(t *testing.T) {
				dir, err := os.MkdirTemp(base, "compressed-replacement-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(dir)
				path := filepath.Join(dir, "source")
				attrPath, forkPath := filepath.Join(dir, "attr"), "-"
				if err := os.WriteFile(attrPath, tc.Attribute, 0600); err != nil {
					t.Fatal(err)
				}
				if len(tc.Fork) > 0 {
					forkPath = filepath.Join(dir, "fork")
					if err := os.WriteFile(forkPath, tc.Fork, 0600); err != nil {
						t.Fatal(err)
					}
				}
				run(producer, "install", path, attrPath, forkPath, filepath.Join(dir, "installed"))
				source, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				if err := SetXattr(source, "user.replacement", []byte("independent metadata")); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fchflags(int(source.Fd()), int(UFCompressed)|unix.UF_HIDDEN); err != nil {
					t.Fatal(err)
				}
				// Use a historical birth time so each writer's current mtime cannot
				// clamp it differently during the logical rewrite.
				if err := SetCreationTime(source, time.Unix(1600000000, 0)); err != nil {
					t.Fatal(err)
				}
				// Force the source mtime before destination creation so clamping is
				// exercised deterministically, even across wall-clock second boundaries.
				if err := os.Chtimes(path, time.Unix(1610000000, 0), time.Unix(1610000000, 0)); err != nil {
					t.Fatal(err)
				}
				before := replacementSnapshotOf(t, source)
				limits := XattrCaptureLimits{MaxXattrListSize, MaxXattrReadSize, MaxXattrReadSize}
				storageBefore, err := CaptureXattrs(t.Context(), source, limits)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(storageBefore[DecmpfsName], tc.Attribute) || !bytes.Equal(storageBefore[ResourceForkName], tc.Fork) {
					t.Fatal("installed storage differs")
				}

				if before.Flags&UFCompressed == 0 {
					t.Fatal("source not compressed")
				}
				r, err := prepare(source, dir)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				payload := []byte("rewritten logical contents")
				if _, err := r.File.WriteAt(payload, 0); err != nil {
					t.Fatal(err)
				}
				if err := r.File.Truncate(int64(len(payload))); err != nil {
					t.Fatal(err)
				}
				if err := r.RestoreMetadata(); err != nil {
					t.Fatal(err)
				}
				after := replacementSnapshotOf(t, r.File)
				native := filepath.Join(dir, "native")
				nativeBegin := time.Now().Unix()
				var nativeTimes replacementNativeTimes
				if err := json.Unmarshal(run(oracle, path, native), &nativeTimes); err != nil {
					t.Fatal(err)
				}
				nativeEnd := time.Now().Unix()
				f, err := os.Open(native)
				if err != nil {
					t.Fatal(err)
				}
				control := replacementSnapshotOf(t, f)
				// The foreign borrowed API must select the same complete attribute
				// set as independent native copyfile, including fork ownership.
				nativeValues, err := CaptureXattrs(t.Context(), f, limits)
				if err != nil {
					t.Fatal(err)
				}
				borrowed := make(map[string]appledouble.Value, len(storageBefore))
				for name, data := range storageBefore {
					borrowed[name] = bytes.NewReader(data)
				}
				selected, err := ReplacementAttributeValues(t.Context(), before.Flags, borrowed)
				if err != nil || len(selected) != len(nativeValues) {
					t.Fatal("foreign/native attribute selection", selected, nativeValues, err)
				}
				for name, value := range selected {
					data, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
					if err != nil || !bytes.Equal(data, nativeValues[name]) {
						t.Fatal("foreign/native attribute bytes", name, err)
					}
				}

				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				if after.Flags != before.Flags&^UFCompressed || after.Attributes[DecmpfsName] != "" {
					t.Fatal("stale compression", after)
				}
				// COPYFILE_METADATA copies mtime, which clamps destination birth; the SDK
				// explicitly preserves source birth time. Qualify both contracts
				// separately and retain both unmodified snapshots in the record.
				if after.Birth != before.Birth {
					t.Fatal("source birth time lost", after.Birth, before.Birth)
				}
				if err := nativeTimes.validate(replacementNativeTime{control.Birth.Sec, control.Birth.Nsec}); err != nil {
					t.Fatal(err)
				}
				if nativeTimes.SourceModified != (replacementNativeTime{1610000000, 0}) {
					t.Fatal("source modification time not installed", nativeTimes)
				}
				equivalent := control
				equivalent.Birth = before.Birth
				if !reflect.DeepEqual(after, equivalent) {
					t.Fatalf("SDK vs native metadata:\n%+v\n%+v", after, control)
				}
				storageAfter, err := CaptureXattrs(t.Context(), source, limits)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(storageBefore, storageAfter) {
					t.Fatal("source compression storage changed")
				}
				if !reflect.DeepEqual(before, replacementSnapshotOf(t, source)) {
					t.Fatal("source metadata changed")
				}
				if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, tc.Plain) {
					t.Fatal("source content changed", err)
				}
				for _, p := range []string{r.File.Name(), native} {
					if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, payload) {
						t.Fatal("replacement content", err)
					}
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if entry.IsDir() {
						t.Fatal("stage leaked", entry.Name())
					}
				}
				record := map[string]any{"case": t.Name(), "type": tc.Type, "filesystem": os.Getenv("APFS_REPLACEMENT_FS"), "source": before, "replacement": after, "native": control, "native_times": nativeTimes, "native_begin": nativeBegin, "native_end": nativeEnd, "source_unchanged": true, "stage_removed": true}
				b, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("COMPRESSED_REPLACEMENT_NATIVE %s", b)
			})
		}
	})
}

// RestoreMetadata must preserve storage that the caller deliberately installed
// on the replacement, without copying UF_COMPRESSED from an unrelated source.
func TestReplacementCompressedTargetState(t *testing.T) {
	samples := replacementCompressionSamples(t)
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		for _, sample := range samples {
			if sample.Name != "kernel-type1" && sample.Name != "native-10-dense" {
				continue
			}
			t.Run(sample.Name, func(t *testing.T) {
				source, err := os.Create(filepath.Join(t.TempDir(), "source"))
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				if _, err := source.WriteString("original source"); err != nil {
					t.Fatal(err)
				}
				r, err := prepare(source, t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				if err := r.File.Truncate(0); err != nil {
					t.Fatal(err)
				}
				if err := SetXattr(r.File, DecmpfsName, sample.Attribute); err != nil {
					t.Fatal(err)
				}
				if len(sample.Fork) > 0 {
					if err := SetXattr(r.File, ResourceForkName, sample.Fork); err != nil {
						t.Fatal(err)
					}
				}
				if err := unix.Fchflags(int(r.File.Fd()), int(UFCompressed)); err != nil {
					t.Fatal(err)
				}
				if err := r.RestoreMetadata(); err != nil {
					t.Fatal(err)
				}
				if got := replacementSnapshotOf(t, r.File); got.Flags&UFCompressed == 0 {
					t.Fatal("target compression lost")
				}
				got, err := os.ReadFile(r.File.Name())
				if err != nil || !bytes.Equal(got, sample.Plain) {
					t.Fatal("target compression contents", err)
				}
				if got, err := os.ReadFile(source.Name()); err != nil || string(got) != "original source" {
					t.Fatal("source changed", err)
				}
			})
		}
	})
}
