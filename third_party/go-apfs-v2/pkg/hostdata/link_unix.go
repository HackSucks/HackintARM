//go:build !windows && !plan9

package hostdata

import (
	"os"
	"syscall"
)

// Link returns the inode identity behind fi, so two directory entries naming
// the same file can be recognized as hard links to it rather than as two files.
// ok is false when the platform does not expose it.
func Link(fi os.FileInfo) (LinkIdentity, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return LinkIdentity{}, false
	}
	return LinkIdentity{
		Device: uint64(st.Dev),
		Inode:  uint64(st.Ino),
		Links:  uint64(st.Nlink),
	}, true
}
