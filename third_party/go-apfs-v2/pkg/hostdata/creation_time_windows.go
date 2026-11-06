package hostdata

import (
	"os"
	"time"

	hosttime "github.com/deploymenttheory/go-apfs-v2/internal/hosttime"
	"golang.org/x/sys/windows"
)

func setCreationTime(file *os.File, when time.Time) error {
	ticks, err := hosttime.WindowsTicks(when)
	if err != nil {
		return err
	}
	stamp := windows.Filetime{LowDateTime: uint32(ticks), HighDateTime: uint32(ticks >> 32)}
	return hosttime.SetWindows(file, &stamp, nil, nil)
}

func setFileTimes(file *os.File, modify, access time.Time) error {
	mt, err := hosttime.WindowsTicks(modify)
	if err != nil {
		return err
	}
	at, err := hosttime.WindowsTicks(access)
	if err != nil {
		return err
	}
	m := windows.Filetime{LowDateTime: uint32(mt), HighDateTime: uint32(mt >> 32)}
	a := windows.Filetime{LowDateTime: uint32(at), HighDateTime: uint32(at >> 32)}
	return hosttime.SetWindows(file, nil, &a, &m)
}
