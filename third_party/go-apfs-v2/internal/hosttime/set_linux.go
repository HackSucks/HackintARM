package hosttime

import (
	"os"

	"golang.org/x/sys/unix"
)

func SetLinux(target *os.File, stamps []unix.Timespec) error {
	conn, err := target.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = conn.Control(func(fd uintptr) {
		setErr = unix.UtimesNanoAt(int(fd), "", stamps, unix.AT_EMPTY_PATH)
	})
	if err != nil {
		return err
	}
	return setErr
}
