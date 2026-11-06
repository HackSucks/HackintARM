package hostdata

import (
	"os"

	"golang.org/x/sys/unix"
)

func openPathPayload(name string, flags int, mode uint32, nofollow, protected bool, class int) (*os.File, error) {
	if nofollow {
		info, err := os.Lstat(name)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			flags |= unix.O_SYMLINK
		} else {
			flags |= unix.O_NOFOLLOW
		}
	}
	if protected {
		return OpenProtectedPath(name, flags, class, mode)
	}
	fd, err := unix.Open(name, flags|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func pathUnlink(name string) error { return unix.Unlink(name) }
func pathSingleWriter(file *os.File) error {
	return withXattrDescriptor(file, func(fd int) error { _, err := unix.FcntlInt(uintptr(fd), unix.F_SINGLE_WRITER, 1); return err })
}
