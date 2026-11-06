package hostdata

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func readEntryType(root *os.Root, name string) (os.FileMode, error) {
	file, err := metadataParent(root, name, func(parent *os.File, base string) (*os.File, error) {
		return openWindowsMetadataRights(parent, base, windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES)
	})
	if err != nil {
		var status windows.NTStatus
		if errors.As(err, &status) {
			err = status.Errno()
		}
		return 0, err
	}
	return entryTypeFromFile(file)
}

func entryTypeFromFile(file *os.File) (os.FileMode, error) {
	info, err := file.Stat()
	err = errors.Join(err, file.Close())
	if err != nil {
		return 0, err
	}
	return info.Mode().Type(), nil
}
