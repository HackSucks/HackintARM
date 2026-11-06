//go:build darwin || linux

package hostdata

import (
	"errors"

	"golang.org/x/sys/unix"
)

func getVisibleXattrFD(fd int, name string, buf []byte) (int, error) {
	return unix.Fgetxattr(fd, name, buf)
}
func getVisibleXattrPath(path, name string, buf []byte) (int, error) {
	return unix.Lgetxattr(path, name, buf)
}
func removeVisibleXattrFD(fd int, name string) error { return unix.Fremovexattr(fd, name) }
func removeVisibleXattrPath(path, name string) error { return unix.Lremovexattr(path, name) }
func xattrRangeError(err error) bool                 { return errors.Is(err, unix.ERANGE) }
func strictXattrError(err error) error {
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) {
		return errors.Join(ErrXattrUnsupported, err)
	}
	return err
}
