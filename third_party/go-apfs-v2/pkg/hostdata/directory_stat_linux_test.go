package hostdata

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func directoryStatExpectedMode(mode uint32, _ unix.Statfs_t) uint32 { return mode }
func directoryStatAccess(s unix.Stat_t) time.Time                   { return time.Unix(s.Atim.Sec, s.Atim.Nsec) }

func TestCopyDirectoryStatLinuxXattrs(t *testing.T) {
	source, target := directoryStatFixture(t), directoryStatFixture(t)
	for f, value := range map[int]string{int(source.Fd()): "source", int(target.Fd()): "target"} {
		if err := unix.Fsetxattr(f, "user.directory-stat", []byte(value), 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := CopyDirectoryStat(source, target); err != nil {
		t.Fatal(err)
	}
	var data [32]byte
	n, err := unix.Fgetxattr(int(target.Fd()), "user.directory-stat", data[:])
	if err != nil || string(data[:n]) != "target" {
		t.Fatalf("target xattr: %q %v", data[:n], err)
	}
}
