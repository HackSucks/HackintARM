package hostdata

import (
	"os"

	"golang.org/x/sys/unix"
)

func openMetadataFileRead(root *os.Root, name string, info os.FileInfo) (*os.File, error) {
	return openMetadataFile(root, name, info)
}

func openMetadataFile(root *os.Root, name string, info os.FileInfo) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if info.Mode()&os.ModeSymlink != 0 {
		flags |= unix.O_PATH
	}
	return root.OpenFile(name, flags, 0)
}
