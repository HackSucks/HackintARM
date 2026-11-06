package hostdata

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"syscall"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestCommitHeldCompressionNativeReadback(t *testing.T)  { compressionHeldNativeReadback(t, false) }
func TestInstallHeldCompressionNativeReadback(t *testing.T) { compressionHeldNativeReadback(t, true) }
func compressionHeldNativeReadback(t *testing.T, install bool) {
	count := 0
	for index, c := range compressionLifecycleTrials(t) {
		if c.Scenario != "ordinary" && c.Scenario != "multi-block" || c.Fault != "" {
			continue
		}
		count++
		t.Run(fmt.Sprintf("%d/%s/%s/%s", index, c.Filesystem, c.Requested, c.Inline), func(t *testing.T) {
			base := os.Getenv("APFS_COMPRESSION_MOUNT")
			if base == "" {
				base = t.TempDir()
			}
			f, e := os.CreateTemp(base, "commit-held-")
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			path := f.Name()
			defer os.Remove(path)
			if _, e = f.Write(c.Data); e != nil {
				t.Fatal(e)
			}
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
			if !install && len(c.Fork) > 0 {
				if n, e := ReplaceResourceFork(t.Context(), f, bytes.NewReader(c.Fork)); e != nil || n != int64(len(c.Fork)) {
					t.Fatal(n, e)
				}
			}
			heldPath := path + "-held"
			if e = os.Rename(path, heldPath); e != nil {
				t.Fatal(e)
			}
			defer os.Remove(heldPath)
			if e = os.WriteFile(path, []byte("unrelated replacement"), 0600); e != nil {
				t.Fatal(e)
			}
			var r CompressionCommitResult
			storage := decmpfs.EncodedFile{Attribute: c.Attribute, ForkSize: int64(len(c.Fork))}
			if install {
				var installed CompressionInstallationResult
				installed, e = InstallHeldCompression(t.Context(), f, storage, bytes.NewReader(c.Fork), source)
				r = installed.Commit
				if !installed.Fork.Complete || len(installed.Fork.Failures) != 0 {
					t.Fatal(installed, e)
				}
			} else {
				r, e = CommitHeldCompression(t.Context(), f, storage, source)
			}

			if e != nil || !r.Completed || !r.Activated || !r.TimesRestored || len(r.Failures) != 0 {
				t.Fatal(r, e)
			}
			after, e := metadata.CaptureStat()
			if e != nil {
				t.Fatal(e)
			}
			if after.Flags != UFCompressed || after.Mode != source.Mode || !after.Times.Modify.Equal(source.Times.Modify.Truncate(time.Microsecond)) || !after.Times.Access.Equal(source.Times.Access.Truncate(time.Microsecond)) {
				t.Fatal("native metadata differs", source, after)
			}
			info, e := f.Stat()
			if e != nil || !os.SameFile(before, info) || info.Size() != int64(len(c.Data)) {
				t.Fatal(info, e)
			}
			got := make([]byte, len(c.Data))
			n, e := f.ReadAt(got, 0)
			if e != nil || n != len(got) || !bytes.Equal(got, c.Data) {
				t.Fatal("held native kernel readback", n, e)
			}
			got, e = os.ReadFile(heldPath)
			if e != nil || !bytes.Equal(got, c.Data) {
				t.Fatal("reopened native kernel readback", e)
			}
			got, e = os.ReadFile(path)
			if e != nil || string(got) != "unrelated replacement" {
				t.Fatal("redirected transition", e)
			}
		})
	}
	if count != 66 {
		t.Fatal("incomplete native storage inventory", count)
	}
}

func TestCommitHeldCompressionNativeErrors(t *testing.T) {
	if _, e := newHeldCompressionCommit(nil); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	dir, e := os.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	if _, e = newHeldCompressionCommit(dir); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	f, e := os.CreateTemp(t.TempDir(), "errors-")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	backend, e := newHeldCompressionCommit(f)
	if e != nil {
		t.Fatal(e)
	}
	metadata, e := NewHeldMetadata(f)
	if e != nil {
		t.Fatal(e)
	}
	// A real deny-write-extattr ACL distinguishes native EACCES from EPERM.
	if output, e := cirunner.Command("/bin/chmod", "+a", "everyone deny writeextattr", f.Name()).CombinedOutput(); e != nil {
		t.Fatal(e, string(output))
	}
	e = backend.SetCompressionAttribute(compressionMetadataHeader(8)[:16])
	if !errors.Is(e, ErrCompressionAttributeAccess) || !errors.Is(e, syscall.EACCES) {
		t.Fatal(e)
	}
	if output, e := cirunner.Command("/bin/chmod", "-N", f.Name()).CombinedOutput(); e != nil {
		t.Fatal(e, string(output))
	}
	if e = unix.Fchflags(int(f.Fd()), unix.UF_IMMUTABLE); e != nil {
		t.Fatal(e)
	}
	e = backend.SetCompressionAttribute(compressionMetadataHeader(8)[:16])
	clearErr := unix.Fchflags(int(f.Fd()), 0)
	if !errors.Is(e, syscall.EPERM) || errors.Is(e, ErrCompressionAttributeAccess) || clearErr != nil {
		t.Fatal(e, clearErr)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = bindHeldCompressionCommit(f, metadata); !errors.Is(e, os.ErrClosed) {
		t.Fatal(e)
	}
	for _, call := range []func() error{func() error { return backend.SetCompressionAttribute([]byte("closed")) }, func() error { return backend.TruncateData(0) }, backend.SyncData, func() error { return backend.SetCompressionTimes(time.Unix(0, 0), time.Unix(0, 0)) }} {
		if e = call(); e == nil {
			t.Fatal("closed descriptor accepted")
		}
	}
}
