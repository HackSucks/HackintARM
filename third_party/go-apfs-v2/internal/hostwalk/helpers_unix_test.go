//go:build darwin || linux

package hostwalk

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func makeFIFO(t *testing.T, path string) bool {
	t.Helper()
	return syscall.Mkfifo(path, 0644) == nil
}

func setXattr(t *testing.T, path, name string, value []byte) bool {
	t.Helper()
	return unix.Lsetxattr(path, name, value, 0) == nil
}
