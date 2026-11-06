package hostdata

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func openContentAt(parent *os.File, base string) (*os.File, error) {
	file, err := openWindowsMetadataRights(parent, base, windows.SYNCHRONIZE|windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES)
	var status windows.NTStatus
	if errors.As(err, &status) {
		err = status.Errno()
	}
	return file, err
}
