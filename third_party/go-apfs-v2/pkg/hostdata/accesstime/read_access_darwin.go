package accesstime

import (
	"os"

	"golang.org/x/sys/unix"
)

func recordReadAccess(file *os.File) error {
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	// Darwin may update access time even when mmap rejects a write-only handle.
	if flags&unix.O_ACCMODE == unix.O_WRONLY || flags&unix.O_EVTONLY != 0 {
		return unix.EACCES
	}
	// Mapping records native read access without requiring timestamp-write
	// permission. Never dereference the mapping: even an empty file is safe.
	mapping, err := unix.Mmap(int(file.Fd()), 0, 1, unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		return err
	}
	return unix.Munmap(mapping)
}
