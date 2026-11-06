package hosttime

import (
	"os"

	"golang.org/x/sys/windows"
)

func SetWindows(file *os.File, creation, access, modify *windows.Filetime) error {
	conn, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = conn.Control(func(fd uintptr) {
		setErr = windows.SetFileTime(windows.Handle(fd), creation, access, modify)
	})
	if err != nil {
		return err
	}
	return setErr
}
