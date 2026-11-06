package hostdata

import (
	"golang.org/x/sys/windows"
	"os"
)

func replacementSparse(file *os.File) error {
	var returned uint32
	return windows.DeviceIoControl(windows.Handle(file.Fd()), windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &returned, nil)
}
