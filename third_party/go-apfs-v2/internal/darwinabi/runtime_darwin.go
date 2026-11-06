//go:build darwin

// Package darwinabi extends x/sys's typed Darwin libSystem wrappers for APIs
// which its public surface does not yet expose. No generic FFI or dynamic symbol
// lookup is available. Policy, serialization and lifecycle logic stay in Go.
package darwinabi

import (
	"syscall"
	_ "unsafe"
)

// The Go runtime captures errno within the call before returning to Go. These
// are the same runtime entry points used by golang.org/x/sys/unix v0.48.0.
//
// syscall3 preserves the ARM64 varargs stack placement used by x/sys fcntl.
// Padding fcntl to six arguments puts the wrong argument on that stack slot.
//
//go:linkname syscall3 syscall.syscall
func syscall3(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname syscall6 syscall.syscall6
func syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname syscall6X syscall.syscall6X
func syscall6X(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

// Passwd matches the public Darwin pwd.h record. Only Name and UID are read.
type Passwd struct {
	Name, Password            *byte
	UID, GID                  uint32
	Change                    int64
	Class, Gecos, Home, Shell *byte
	Expire                    int64
}

// Group matches the public Darwin grp.h record. Only Name and GID are read.
type Group struct {
	Name, Password *byte
	GID            uint32
	Members        **byte
}
