package accesstime

import (
	"bytes"
	"errors"
	"io"
	"os"

	"path/filepath"
	"syscall"
	"testing"
	"time"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestRecordReadAccessDarwinHeldFile(t *testing.T) {
	for _, profile := range []string{"past", "future", "empty"} {
		t.Run(profile, func(t *testing.T) {
			file := heldfixture.Source(t, 0600)
			original, moved := file.Name(), file.Name()+".moved"
			if profile == "empty" {
				if err := os.Truncate(original, 0); err != nil {
					t.Fatal(err)
				}
			}
			content, err := os.ReadFile(original)
			if err != nil {
				t.Fatal(err)
			}
			access := time.Unix(978307200, 234567890)
			if profile == "future" {
				access = time.Now().Add(48 * time.Hour)
			}
			if err := os.Chtimes(original, access, time.Unix(946684800, 123456789)); err != nil {
				t.Fatal(err)
			}
			if err := unix.Setxattr(original, "org.example.read-access", []byte("retained"), 0); err != nil {
				t.Fatal(err)
			}
			if err := unix.Chflags(original, unix.UF_HIDDEN); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(original, 0400); err != nil {
				t.Fatal(err)
			}
			if out, err := cirunner.Command("/bin/chmod", "+a", "everyone deny writeattr", original).CombinedOutput(); err != nil {
				t.Fatalf("ACL: %v: %s", err, out)
			}
			if err := os.Rename(original, moved); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cirunner.Command("/bin/chmod", "-N", moved).Run() })
			if err := os.WriteFile(original, []byte("neighbour"), 0600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(filepath.Dir(moved), "linked")
			if err := os.Link(moved, link); err != nil {
				t.Fatal(err)
			}
			if _, err := file.Seek(1, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			stat := func(path string) syscall.Stat_t {
				t.Helper()
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				return *info.Sys().(*syscall.Stat_t)
			}
			acl := func() []byte {
				out, err := cirunner.Command("/bin/ls", "-lde", moved).CombinedOutput()
				if err != nil {
					t.Fatal(err)
				}
				_, value, _ := bytes.Cut(out, []byte{'\n'})
				return value
			}
			before, neighbour, beforeACL := stat(moved), stat(original), acl()
			started := time.Now()
			if err := RecordReadAccess(file); err != nil {
				t.Fatal(err)
			}
			finished := time.Now()
			after := stat(moved)
			got := time.Unix(after.Atimespec.Sec, after.Atimespec.Nsec)
			if got.Before(started) || got.After(finished) {
				t.Fatalf("access time %v outside [%v, %v]", got, started, finished)
			}
			before.Atimespec = after.Atimespec
			if before != after || !bytes.Equal(beforeACL, acl()) || stat(original) != neighbour {
				t.Fatal("unrelated metadata, ACL or reused pathname changed")
			}
			if linked := stat(link); linked.Ino != after.Ino || linked.Atimespec != after.Atimespec {
				t.Fatal("hard link does not reflect read access")
			}
			if offset, err := file.Seek(0, io.SeekCurrent); err != nil || offset != 1 {
				t.Fatalf("file position: %d, %v", offset, err)
			}
			value := make([]byte, 32)
			n, err := unix.Fgetxattr(int(file.Fd()), "org.example.read-access", value)
			if err != nil || string(value[:n]) != "retained" {
				t.Fatalf("xattr: %v", err)
			}
			if got, err := os.ReadFile(moved); err != nil || !bytes.Equal(got, content) {
				t.Fatalf("contents changed: %v", err)
			}
		})
	}
}

func TestRecordReadAccessDarwinUnreadableDescriptor(t *testing.T) {
	for name, flags := range map[string]int{"write-only": os.O_WRONLY, "event-only": unix.O_EVTONLY} {
		t.Run(name, func(t *testing.T) {
			source := heldfixture.Source(t, 0600)
			file, err := os.OpenFile(source.Name(), flags, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			before, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if err := RecordReadAccess(file); !errors.Is(err, os.ErrPermission) {
				t.Fatalf("unreadable descriptor: %v", err)
			}
			after, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if *before.Sys().(*syscall.Stat_t) != *after.Sys().(*syscall.Stat_t) {
				t.Fatal("failed recording changed metadata")
			}
		})
	}
}
