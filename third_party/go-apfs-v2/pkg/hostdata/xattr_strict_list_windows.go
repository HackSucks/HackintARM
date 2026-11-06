package hostdata

import (
	"errors"
	"io"

	"golang.org/x/sys/windows"
)

func listVisibleXattrFD(fd, limit int) ([]string, error) {
	handle, err := reopenXattrHandle(windows.Handle(fd), windows.FILE_READ_EA)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)
	return readXattrEAs(func(buf []byte, restart bool) (int, error) {
		var status windows.IO_STATUS_BLOCK
		err := windows.NtQueryEaFile(handle, &status, &buf[0], uint32(len(buf)), true, nil, 0, nil, restart)
		return int(status.Information), listWindowsEAError(err, restart)
	}, limit)
}

func listWindowsEAError(err error, restart bool) error {
	if errors.Is(err, windows.STATUS_NO_MORE_EAS) || (restart && errors.Is(err, windows.STATUS_NO_EAS_ON_FILE)) {
		return io.EOF
	}
	if errors.Is(err, windows.STATUS_NO_EAS_ON_FILE) {
		return errors.Join(ErrXattrChanged, err)
	}
	return err
}
