package hostdata

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func statMetadata(root *os.Root, name string) (os.FileInfo, error) {
	file, err := metadataParent(root, name, func(parent *os.File, base string) (*os.File, error) {
		// Do not request FILE_READ_DATA or FILE_READ_EA: neither is part of the
		// discovery authorization contract. Root.Lstat currently opens GENERIC_READ.
		return openWindowsMetadataRights(parent, base, windows.SYNCHRONIZE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	})
	if err != nil {
		var status windows.NTStatus
		if errors.As(err, &status) {
			err = &os.PathError{Op: "statmetadata", Path: name, Err: status.Errno()}
		}
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}
