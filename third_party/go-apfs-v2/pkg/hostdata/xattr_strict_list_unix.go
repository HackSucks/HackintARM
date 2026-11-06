//go:build darwin || linux

package hostdata

import "golang.org/x/sys/unix"

func listVisibleXattrFD(fd, limit int) ([]string, error) {
	return readXattrNames(func(buf []byte) (int, error) { return unix.Flistxattr(fd, buf) }, limit)
}
