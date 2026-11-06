package accesstime

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func copyAccessTime(target *os.File, source os.FileInfo) error {
	when := source.Sys().(*syscall.Stat_t).Atimespec
	var timestamp [16]byte
	binary.LittleEndian.PutUint64(timestamp[:], uint64(when.Sec))
	binary.LittleEndian.PutUint64(timestamp[8:], uint64(when.Nsec))
	list := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_ACCTIME}
	// fdescfs binds Setattrlist to the held file despite pathname replacement.
	return unix.Setattrlist(fmt.Sprintf("/dev/fd/%d", target.Fd()), &list, timestamp[:], 0)
}
