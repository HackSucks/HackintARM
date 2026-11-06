//go:build darwin

package bsdflags

import (
	"os"
	"syscall"
)

// Flags returns the file's BSD flags (st_flags): uchg, hidden, opaque and the
// rest. ok is false when the platform has no such field.
func Flags(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Flags, true
}
