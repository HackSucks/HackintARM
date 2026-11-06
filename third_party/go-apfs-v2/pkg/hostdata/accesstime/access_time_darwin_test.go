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

func accessTimeStat(t *testing.T, file *os.File) syscall.Stat_t {
	t.Helper()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return *info.Sys().(*syscall.Stat_t)
}

func TestCopyAccessTimeDarwinHeldFiles(t *testing.T) {
	for _, profile := range []string{"past", "future", "mapped-read"} {
		for _, mode := range []os.FileMode{0600, 0400} {
			t.Run(profile+"/"+mode.String(), func(t *testing.T) {
				source, target := heldfixture.Source(t, 0600), heldfixture.Source(t, 0600)
				when := time.Unix(978307200, 234567891)
				if profile == "future" {
					when = time.Now().Add(48 * time.Hour)
				}
				if err := os.Chtimes(source.Name(), when, time.Unix(946684800, 123456789)); err != nil {
					t.Fatal(err)
				}
				if profile == "mapped-read" {
					if err := RecordReadAccess(source); err != nil {
						t.Fatal(err)
					}
				}
				if out, err := cirunner.Command("/bin/chmod", "+a", "everyone allow read", target.Name()).CombinedOutput(); err != nil {
					t.Fatalf("ACL: %v: %s", err, out)
				}
				if err := unix.Fsetxattr(int(target.Fd()), "org.example.access-copy", []byte("retained"), 0); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fchflags(int(target.Fd()), unix.UF_HIDDEN); err != nil {
					t.Fatal(err)
				}
				if err := target.Chmod(mode); err != nil {
					t.Fatal(err)
				}
				type namedFile struct {
					file            *os.File
					moved, original string
					decoy           syscall.Stat_t
				}
				var files []namedFile
				for _, file := range []*os.File{source, target} {
					name, moved := file.Name(), file.Name()+".moved"
					if err := os.Rename(name, moved); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(name, []byte("decoy"), 0600); err != nil {
						t.Fatal(err)
					}
					info, err := os.Stat(name)
					if err != nil {
						t.Fatal(err)
					}
					files = append(files, namedFile{file, moved, name, *info.Sys().(*syscall.Stat_t)})
					if _, err := file.Seek(2, io.SeekStart); err != nil {
						t.Fatal(err)
					}
				}
				neighbour := filepath.Join(t.TempDir(), "linked-target")
				if err := os.Link(files[1].moved, neighbour); err != nil {
					t.Fatal(err)
				}
				acl := func() []byte {
					out, err := cirunner.Command("/bin/ls", "-lde", files[1].moved).CombinedOutput()
					if err != nil {
						t.Fatal(err)
					}
					_, entries, _ := bytes.Cut(out, []byte{'\n'})
					return entries
				}
				beforeACL := acl()
				from, to := accessTimeStat(t, source), accessTimeStat(t, target)
				if err := CopyAccessTime(source, target); err != nil {
					t.Fatal(err)
				}
				after := accessTimeStat(t, target)
				if after.Atimespec != from.Atimespec {
					t.Fatalf("access time: got %#v want %#v", after.Atimespec, from.Atimespec)
				}
				to.Atimespec, to.Ctimespec = after.Atimespec, after.Ctimespec
				if to != after || !bytes.Equal(beforeACL, acl()) {
					t.Fatal("unrelated target metadata changed")
				}
				if accessTimeStat(t, source) != from {
					t.Fatal("source metadata changed")
				}
				linked, err := os.Stat(neighbour)
				if err != nil {
					t.Fatal(err)
				}
				if *linked.Sys().(*syscall.Stat_t) != after {
					t.Fatal("target hard link differs")
				}
				value := make([]byte, 32)
				n, err := unix.Fgetxattr(int(target.Fd()), "org.example.access-copy", value)
				if err != nil || string(value[:n]) != "retained" {
					t.Fatalf("xattr: %v", err)
				}
				for _, f := range files {
					info, err := os.Stat(f.original)
					if err != nil {
						t.Fatal(err)
					}
					if *info.Sys().(*syscall.Stat_t) != f.decoy {
						t.Fatal("old pathname modified")
					}
					pos, err := f.file.Seek(0, io.SeekCurrent)
					if err != nil || pos != 2 {
						t.Fatalf("file position: %d: %v", pos, err)
					}
					data, err := os.ReadFile(f.moved)
					if err != nil || string(data) != "original contents longer than the replacement" {
						t.Fatalf("contents: %q: %v", data, err)
					}
				}
			})
		}
	}
}

func TestCopyAccessTimeDarwinDenied(t *testing.T) {
	for _, protection := range []string{"immutable", "deny-writeattr"} {
		t.Run(protection, func(t *testing.T) {
			source, target := heldfixture.Source(t, 0600), heldfixture.Source(t, 0600)
			switch protection {
			case "immutable":
				if err := unix.Fchflags(int(target.Fd()), unix.UF_IMMUTABLE); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = unix.Chflags(target.Name(), 0) })
			case "deny-writeattr":
				if out, err := cirunner.Command("/bin/chmod", "+a", "everyone deny writeattr", target.Name()).CombinedOutput(); err != nil {
					t.Fatalf("ACL: %v: %s", err, out)
				}
				t.Cleanup(func() { _ = cirunner.Command("/bin/chmod", "-N", target.Name()).Run() })
			}
			from, to := accessTimeStat(t, source), accessTimeStat(t, target)
			if err := CopyAccessTime(source, target); !errors.Is(err, os.ErrPermission) {
				t.Fatalf("protected copy: %v", err)
			}
			if from != accessTimeStat(t, source) || to != accessTimeStat(t, target) {
				t.Fatal("failed copy changed metadata")
			}
		})
	}
}
