package hostdata

import (
	"os"
	"time"

	hosttime "github.com/deploymenttheory/go-apfs-v2/internal/hosttime"
	"golang.org/x/sys/unix"
)

func setFileTimes(target *os.File, modify, access time.Time) error {
	return hosttime.SetLinux(target, []unix.Timespec{
		{Sec: access.Unix(), Nsec: int64(access.Nanosecond())},
		{Sec: modify.Unix(), Nsec: int64(modify.Nanosecond())},
	})
}
