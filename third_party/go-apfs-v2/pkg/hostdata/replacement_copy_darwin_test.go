package hostdata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestReplacementCopyCloneErrors(t *testing.T) {
	for _, err := range []error{unix.ENOTSUP, unix.EXDEV, unix.ENOSYS} {
		if !replacementCloneUnavailable(fmt.Errorf("clone: %w", err)) {
			t.Fatalf("not classified: %v", err)
		}
	}
	for _, err := range []error{nil, unix.EPERM, unix.EACCES, unix.ENOSPC, unix.EIO, unix.EINVAL, unix.ENOENT, unix.EEXIST} {
		if replacementCloneUnavailable(err) {
			t.Fatalf("error suppressed: %v", err)
		}
	}
}

type replacementSnapshot struct {
	Mode, UID, GID, Flags uint32
	Birth                 syscall.Timespec
	Attributes            map[string]string
	ForkSize              int64
	ForkSHA256            string
	ACL                   *appledouble.ACL
}

func replacementSnapshotOf(t *testing.T, file *os.File) replacementSnapshot {
	t.Helper()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	result := replacementSnapshot{Mode: uint32(stat.Mode), UID: stat.Uid, GID: stat.Gid, Flags: stat.Flags, Birth: stat.Birthtimespec, Attributes: map[string]string{}}
	names, err := ListXattrNames(file, MaxXattrListSize)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if name == "com.apple.ResourceFork" {
			fork, err := OpenResourceFork(file, false)
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.New()
			result.ForkSize, err = io.Copy(hash, fork)
			closeErr := fork.Close()
			if err != nil || closeErr != nil {
				t.Fatal(errors.Join(err, closeErr))
			}
			result.ForkSHA256 = hex.EncodeToString(hash.Sum(nil))
		} else {
			value, present, err := ReadXattr(file, name, MaxXattrReadSize)
			if err != nil || !present {
				t.Fatalf("read %s: %v", name, err)
			}
			result.Attributes[name] = hex.EncodeToString(value)
		}
	}
	held, err := NewHeldMetadata(file)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := held.CaptureACL()
	if err != nil {
		t.Fatal(err)
	}
	result.ACL = acl.Security.ACL
	return result
}

func TestReplacementCopyDarwinNative(t *testing.T) {
	base := os.Getenv("APFS_REPLACEMENT_MOUNT")
	if base == "" {
		base = t.TempDir()
	}
	oracle := os.Getenv("APFS_REPLACEMENT_ORACLE")
	if oracle == "" {
		oracle = filepath.Join(t.TempDir(), "oracle")
		output, err := cirunner.Command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "../../testdata/appledouble/native/replacement-copy.c", "-o", oracle).CombinedOutput()
		if err != nil {
			t.Fatalf("compile oracle: %v\n%s", err, output)
		}
	}
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		for _, deny := range []bool{false, true} {
			t.Run(fmt.Sprintf("deny-write-%t", deny), func(t *testing.T) {
				dir, err := os.MkdirTemp(base, "replacement-native-")
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.RemoveAll(dir); err != nil {
						t.Error(err)
					}
				}()
				source, err := os.OpenFile(filepath.Join(dir, "source"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				content := []byte("original data stays untouched")
				if _, err := source.Write(content); err != nil {
					t.Fatal(err)
				}
				for name, value := range map[string][]byte{"user.replacement": {1, 2, 3}, "user.empty": {}, "com.apple.quarantine": []byte("0081;65000000;ReplacementTest;12345678-1234-1234-1234-123456789abc"), "com.apple.FinderInfo": append([]byte("TEXTtest"), make([]byte, 24)...)} {
					if err := SetXattr(source, name, value); err != nil {
						t.Fatal(err)
					}
				}
				payload := bytes.Repeat([]byte{0x73}, MaxXattrReadSize+37)
				if _, err := ReplaceResourceFork(t.Context(), source, io.NewSectionReader(bytes.NewReader(payload), 0, int64(len(payload)))); err != nil {
					t.Fatal(err)
				}
				if err := SetCreationTime(source, time.Unix(1600000000, 0)); err != nil {
					t.Fatal(err)
				}
				if err := source.Chmod(0551); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fchflags(int(source.Fd()), unix.UF_HIDDEN); err != nil {
					t.Fatal(err)
				}
				if deny {
					output, err := cirunner.Command("/bin/chmod", "+a", "everyone deny write", source.Name()).CombinedOutput()
					if err != nil {
						t.Fatalf("ACL: %v %s", err, output)
					}
				}
				parent := filepath.Join(dir, "parent")
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
				output, err := cirunner.Command("/bin/chmod", "+a", "everyone allow read,file_inherit,directory_inherit", parent).CombinedOutput()
				if err != nil {
					t.Fatalf("inheritance: %v %s", err, output)
				}
				before := replacementSnapshotOf(t, source)
				nativePath := filepath.Join(parent, "native")
				output, err = cirunner.Command(oracle, source.Name(), nativePath, filepath.Join(parent, "clone")).CombinedOutput()
				if err != nil {
					t.Fatalf("native oracle: %v %s", err, output)
				}
				var outcomes replacementNativeOutcome
				if err := json.Unmarshal(output, &outcomes); err != nil {
					t.Fatal(err)
				}
				expected := os.Getenv("APFS_REPLACEMENT_FS")
				if expected == "HFS+" && outcomes.CloneErrno != int(unix.ENOTSUP) {
					t.Fatalf("HFS+ clone outcome: %+v", outcomes)
				}
				if expected == "APFS" && outcomes.CloneErrno != 0 {
					t.Fatalf("APFS clone outcome: %+v", outcomes)
				}
				native, err := os.Open(nativePath)
				if err != nil {
					t.Fatal(err)
				}
				defer native.Close()
				nativeMetadata := replacementSnapshotOf(t, native)
				replacementNativeAttributes(t, before.Attributes, nativeMetadata.Attributes, outcomes)
				if before.ForkSize != nativeMetadata.ForkSize || before.ForkSHA256 != nativeMetadata.ForkSHA256 || before.Mode != nativeMetadata.Mode || before.UID != nativeMetadata.UID || before.GID != nativeMetadata.GID || before.Flags != nativeMetadata.Flags {
					t.Fatalf("native metadata mismatch:\nsource=%+v\nnative=%+v", before, nativeMetadata)
				}
				manual, err := os.Create(filepath.Join(dir, "manual-copy"))
				if err != nil {
					t.Fatal(err)
				}
				defer manual.Close()
				info, err := source.Stat()
				if err != nil {
					t.Fatal(err)
				}
				if err := copyReplacementMetadata(source, manual, info); err != nil {
					t.Fatal(err)
				}
				if err := restoreReplacementMetadataContext(t.Context(), source, manual, info); err != nil {
					t.Fatal(err)
				}
				if got := replacementSnapshotOf(t, manual); !reflect.DeepEqual(got, before) {
					t.Fatalf("explicit fallback metadata: %+v; want %+v", got, before)
				}

				replacement, err := prepare(source, parent)
				if err != nil {
					t.Fatal(err)
				}
				defer replacement.Close()
				held, err := NewHeldMetadata(replacement.File)
				if err != nil {
					t.Fatal(err)
				}
				acl, err := held.CaptureACL()
				if err != nil {
					t.Fatal(err)
				}
				if acl.Security.ACL != nil {
					t.Fatalf("premature ACL: %+v", acl)
				}
				if _, err := replacement.File.WriteAt([]byte("changed"), 0); err != nil {
					t.Fatal(err)
				}
				if err := replacement.File.Truncate(7); err != nil {
					t.Fatal(err)
				}
				if err := replacement.RestoreMetadata(); err != nil {
					t.Fatal(err)
				}
				actual := replacementSnapshotOf(t, replacement.File)
				if !reflect.DeepEqual(actual, before) {
					t.Fatalf("metadata mismatch:\ngo=%+v\nnative=%+v", actual, before)
				}
				sourceData, err := os.ReadFile(source.Name())
				if err != nil || !bytes.Equal(sourceData, content) {
					t.Fatalf("source changed: %v", err)
				}
				if !reflect.DeepEqual(before, replacementSnapshotOf(t, source)) {
					t.Fatal("source metadata changed")
				}
				stagePath := replacement.File.Name()
				if err := replacement.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(stagePath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("staging leaked: %v", err)
				}
				report := map[string]any{"case": t.Name(), "filesystem": expected, "native": outcomes, "native_metadata": nativeMetadata, "source_metadata": before, "replacement_metadata": actual, "copyfile_payload_matches": true, "source_unchanged": true, "staging_removed": true}
				data, err := json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("REPLACEMENT_NATIVE %s", data)
			})
		}
	})
}
