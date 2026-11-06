//go:build darwin || linux

package hostdata

import "golang.org/x/sys/unix"

func setVisibleXattrFD(fd int, name string, value []byte) error {
	return unix.Fsetxattr(fd, name, value, 0)
}
