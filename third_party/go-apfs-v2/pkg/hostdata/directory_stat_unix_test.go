//go:build darwin || linux

package hostdata

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCopyDirectoryStatUnix(t *testing.T) {
	for _, mode := range []os.FileMode{0750, 0711 | os.ModeSetgid | os.ModeSticky, 0751 | os.ModeSetuid} {
		t.Run(mode.String(), func(t *testing.T) {
			source, target := directoryStatFixture(t), directoryStatFixture(t)
			if err := source.Chmod(mode); err != nil {
				t.Fatal(err)
			}
			atime, mtime := time.Unix(1650000000, 123456789), time.Unix(1660000000, 987654321)
			if err := os.Chtimes(source.Name(), atime, mtime); err != nil {
				t.Fatal(err)
			}
			var before unix.Stat_t
			if err := unix.Fstat(int(source.Fd()), &before); err != nil {
				t.Fatal(err)
			}
			if err := CopyDirectoryStat(source, target); err != nil {
				t.Fatal(err)
			}
			var got, unchanged unix.Stat_t
			if err := unix.Fstat(int(target.Fd()), &got); err != nil {
				t.Fatal(err)
			}
			if err := unix.Fstat(int(source.Fd()), &unchanged); err != nil {
				t.Fatal(err)
			}
			wantMode := before.Mode
			var volume unix.Statfs_t
			if err := unix.Fstatfs(int(target.Fd()), &volume); err != nil {
				t.Fatal(err)
			}
			// Darwin's COPYFILE_STAT profile strips privileged bits on nosuid.
			wantMode = directoryStatExpectedMode(wantMode, volume)
			if got.Mode != wantMode || got.Uid != before.Uid || got.Gid != before.Gid {
				t.Fatalf("mode/owner: %#v; want %#v", got, before)
			}
			info, err := target.Stat()
			if err != nil || !info.ModTime().Equal(mtime) {
				t.Fatalf("mtime: %v %v", info, err)
			}
			if gotAtime := directoryStatAccess(got); !gotAtime.Equal(atime) {
				t.Fatalf("atime: %v; want %v", gotAtime, atime)
			}
			if unchanged != before {
				t.Fatalf("source metadata changed: %#v -> %#v", before, unchanged)
			}
		})
	}
}
