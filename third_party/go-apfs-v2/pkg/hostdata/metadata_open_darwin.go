package hostdata

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openMetadataFileRead(root *os.Root, name string, info os.FileInfo) (*os.File, error) {
	return openMetadataFile(root, name, info)
}

func openMetadataFile(root *os.Root, name string, _ os.FileInfo) (*os.File, error) {
	// Darwin O_SYMLINK must replace O_NOFOLLOW: combining them yields ELOOP,
	// which os.Root.OpenFile handles by resolving the link. Hold the contained
	// parent and open its final component directly, without pathname fallback.
	return metadataParent(root, name, openDarwinMetadataAt)
}

func openDarwinMetadataAt(parent *os.File, base string) (*os.File, error) {
	conn, err := parent.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd int
	var callErr error
	err = conn.Control(func(parentFD uintptr) {
		fd, callErr = unix.Openat(int(parentFD), base, unix.O_RDONLY|unix.O_SYMLINK|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	})
	if err = errors.Join(err, callErr); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), base), nil
}
