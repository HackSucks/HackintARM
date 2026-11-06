package hostdata

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func directoryStatExpectedMode(mode uint16, volume unix.Statfs_t) uint16 {
	if volume.Flags&unix.MNT_NOSUID != 0 {
		return mode &^ (unix.S_ISUID | unix.S_ISGID)
	}
	return mode
}
func directoryStatAccess(s unix.Stat_t) time.Time {
	return time.Unix(s.Atim.Sec, s.Atim.Nsec)
}

func TestCopyDirectoryStatDarwinNative(t *testing.T) {
	// This independent oracle links libSystem only in a test helper. The Go API
	// and all production builds remain CGO-free and do not invoke helpers.
	dir := t.TempDir()
	c := filepath.Join(dir, "copy-stat.c")
	const program = `#include <copyfile.h>
#include <stdio.h>
int main(int argc, char **argv) {
  if (argc != 3) return 2;
  if (copyfile(argv[1], argv[2], NULL, COPYFILE_STAT)) { perror("copyfile"); return 1; }
  return 0;
}`
	if err := os.WriteFile(c, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	oracle := filepath.Join(dir, "copy-stat")
	if out, err := cirunner.Command("/usr/bin/clang", "-Wall", "-Werror", c, "-o", oracle).CombinedOutput(); err != nil {
		t.Fatalf("compile oracle: %v: %s", err, out)
	}
	for _, flags := range []int{0, unix.UF_HIDDEN, unix.UF_NODUMP | unix.UF_OPAQUE, unix.UF_TRACKED | unix.UF_HIDDEN} {
		t.Run(fmt.Sprintf("flags-%x", flags), func(t *testing.T) {
			source, target, native := directoryStatFixture(t), directoryStatFixture(t), directoryStatFixture(t)
			if err := source.Chmod(0750 | os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(source.Name(), time.Unix(1650000000, 123456789), time.Unix(1660000000, 987654321)); err != nil {
				t.Fatal(err)
			}
			if err := unix.Fchflags(int(source.Fd()), flags); err != nil {
				t.Fatal(err)
			}
			for _, f := range []*os.File{target, native} {
				if err := unix.Fchflags(int(f.Fd()), unix.UF_HIDDEN|unix.UF_NODUMP); err != nil {
					t.Fatal(err)
				}
			}
			if out, err := cirunner.Command(oracle, source.Name(), native.Name()).CombinedOutput(); err != nil {
				t.Fatalf("copyfile: %v: %s", err, out)
			}
			if err := CopyDirectoryStat(source, target); err != nil {
				t.Fatal(err)
			}
			var got, want unix.Stat_t
			if err := unix.Fstat(int(target.Fd()), &got); err != nil {
				t.Fatal(err)
			}
			if err := unix.Fstat(int(native.Fd()), &want); err != nil {
				t.Fatal(err)
			}
			if got.Mode != want.Mode || got.Uid != want.Uid || got.Gid != want.Gid || got.Flags != want.Flags || got.Atim != want.Atim || got.Mtim != want.Mtim || got.Btim != want.Btim {
				t.Fatalf("Go vs COPYFILE_STAT:\n%#v\n%#v", got, want)
			}
		})
	}
}

func TestCopyDirectoryStatDarwinRetainsACLAndXattrs(t *testing.T) {
	source, target := directoryStatFixture(t), directoryStatFixture(t)
	acl := func(f *os.File, entry string) string {
		if entry != "" {
			if out, err := cirunner.Command("/bin/chmod", "+a", entry, f.Name()).CombinedOutput(); err != nil {
				t.Fatalf("set ACL: %v %s", err, out)
			}
		}
		out, err := cirunner.Command("/bin/ls", "-lde", f.Name()).CombinedOutput()
		if err != nil {
			t.Fatal(err)
		}
		_, entries, _ := bytes.Cut(out, []byte{'\n'})
		return string(entries)
	}
	_ = acl(source, "everyone allow read")
	wantACL := acl(target, "everyone allow execute")
	for f, value := range map[*os.File]string{source: "source", target: "target"} {
		if err := unix.Fsetxattr(int(f.Fd()), "org.example.directory-stat", []byte(value), 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := CopyDirectoryStat(source, target); err != nil {
		t.Fatal(err)
	}
	if got := acl(target, ""); got != wantACL {
		t.Fatalf("ACL changed: %q; want %q", got, wantACL)
	}
	var data [32]byte
	n, err := unix.Fgetxattr(int(target.Fd()), "org.example.directory-stat", data[:])
	if err != nil || string(data[:n]) != "target" {
		t.Fatalf("target xattr: %q %v", data[:n], err)
	}
}

func TestCopyDirectoryStatDarwinRejectsProtectedBeforeMutation(t *testing.T) {
	for _, protectSource := range []bool{true, false} {
		source, target := directoryStatFixture(t), directoryStatFixture(t)
		if err := source.Chmod(0711); err != nil {
			t.Fatal(err)
		}
		protected := target
		if protectSource {
			protected = source
		}
		if err := unix.Fchflags(int(protected.Fd()), unix.UF_IMMUTABLE); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Chflags(protected.Name(), 0) })
		var before, after unix.Stat_t
		if err := unix.Fstat(int(target.Fd()), &before); err != nil {
			t.Fatal(err)
		}
		if err := CopyDirectoryStat(source, target); !errors.Is(err, ErrUnsupportedDirectoryStat) {
			t.Fatalf("protected: %v", err)
		}
		if err := unix.Fstat(int(target.Fd()), &after); err != nil {
			t.Fatal(err)
		}
		if before != after {
			t.Fatalf("rejected operation mutated target: %#v -> %#v", before, after)
		}
	}
}
