package hostdata

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func copyDirectoryStat(_, target *os.File, from, _ os.FileInfo) error {
	src := from.Sys().(*syscall.Stat_t)
	if err := target.Chown(int(src.Uid), int(src.Gid)); err != nil {
		return err
	}
	if err := target.Chmod(from.Mode()); err != nil {
		return err
	}
	// AT_EMPTY_PATH addresses the held directory itself (Linux 5.8+).
	times := []unix.Timespec{{Sec: src.Atim.Sec, Nsec: src.Atim.Nsec}, {Sec: src.Mtim.Sec, Nsec: src.Mtim.Nsec}}
	return unix.UtimesNanoAt(int(target.Fd()), "", times, unix.AT_EMPTY_PATH)
}
