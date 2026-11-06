//go:build !darwin && !linux && !windows

package hostdata

import (
	"errors"
	"os"
)

func openMetadataFileRead(root *os.Root, name string, info os.FileInfo) (*os.File, error) {
	return openMetadataFile(root, name, info)
}

func openMetadataFile(*os.Root, string, os.FileInfo) (*os.File, error) {
	return nil, errors.ErrUnsupported
}
