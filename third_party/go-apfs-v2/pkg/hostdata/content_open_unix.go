//go:build darwin || linux

package hostdata

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openContentAt(parent *os.File, base string) (*os.File, error) {
	conn, err := parent.SyscallConn()
	if err != nil {
		return nil, err
	}
	var fd int
	var openErr error
	err = conn.Control(func(parentFD uintptr) {
		fd, openErr = unix.Openat(int(parentFD), base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	})
	if err = errors.Join(err, openErr); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), base), nil
}
