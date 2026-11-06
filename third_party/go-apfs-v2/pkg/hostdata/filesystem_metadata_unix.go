//go:build darwin || linux

package hostdata

import (
	"os"
	"syscall"
)

func filesystemMetadataSameOwner(a, b os.FileInfo) bool {
	left, lok := a.Sys().(*syscall.Stat_t)
	right, rok := b.Sys().(*syscall.Stat_t)
	return lok && rok && left.Uid == right.Uid
}
