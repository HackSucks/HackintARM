package accesstime

import (
	"os"
	"syscall"

	hosttime "github.com/deploymenttheory/go-apfs-v2/internal/hosttime"
	"golang.org/x/sys/unix"
)

func copyAccessTime(target *os.File, source os.FileInfo) error {
	when := source.Sys().(*syscall.Stat_t).Atim
	return hosttime.SetLinux(target, []unix.Timespec{
		{Sec: when.Sec, Nsec: when.Nsec}, {Nsec: unix.UTIME_OMIT},
	})
}
