package hostdata

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func openPathResourceForkNative(file *os.File, writable bool, mode uint32) (io.Closer, error) {
	return openPathResourceForkUsing(file, writable, mode, openResourceForkAt, (*os.File).Stat)
}

func openPathResourceForkUsing(file *os.File, writable bool, mode uint32,
	open func(int, string, int, uint32) (int, error), stat func(*os.File) (os.FileInfo, error)) (io.Closer, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC
	if writable {
		flags = unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC | unix.O_CLOEXEC
	}
	var fork *os.File
	err := withXattrDescriptor(file, func(fd int) error {
		opened, e := open(fd, "..namedfork/rsrc", flags, mode)
		if e == nil {
			fork = os.NewFile(uintptr(opened), "path resource fork")
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	if !writable {
		if _, err = stat(fork); err != nil {
			return nil, errors.Join(err, fork.Close())
		}
	}
	return fork, nil
}
