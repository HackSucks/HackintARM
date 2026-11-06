package hostdata

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func copyDirectoryStat(source, target *os.File, from, to os.FileInfo) error {
	src, dst := from.Sys().(*syscall.Stat_t), to.Sys().(*syscall.Stat_t)
	// COPYFILE_OMIT_FLAGS in Apple's copyfile_private.h. No new tracked IDs or
	// protected-directory state are transferred from an unrelated directory.
	const omitted = unix.UF_TRACKED | unix.SF_RESTRICTED | unix.SF_NOUNLINK | unix.UF_DATAVAULT
	const supported = unix.UF_NODUMP | unix.UF_OPAQUE | unix.UF_HIDDEN
	if src.Flags & ^uint32(omitted|supported) != 0 || dst.Flags & ^uint32(supported) != 0 {
		return fmt.Errorf("%w: protected or unsupported BSD flags", ErrUnsupportedDirectoryStat)
	}
	mode := from.Mode()
	if mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
		for _, file := range []*os.File{source, target} {
			var volume unix.Statfs_t
			if err := unix.Fstatfs(int(file.Fd()), &volume); err != nil {
				return err
			}
			if volume.Flags&unix.MNT_NOSUID != 0 {
				mode &^= os.ModeSetuid | os.ModeSetgid
			}
		}
	}
	if err := target.Chown(int(src.Uid), int(src.Gid)); err != nil {
		return err
	}
	if err := target.Chmod(mode); err != nil {
		return err
	}
	// Setattrlist's attribute order is modification then access, with native
	// 64-bit timespec fields. fdescfs keeps this tied to the held descriptor.
	var times [32]byte
	binary.LittleEndian.PutUint64(times[0:], uint64(src.Mtimespec.Sec))
	binary.LittleEndian.PutUint64(times[8:], uint64(src.Mtimespec.Nsec))
	binary.LittleEndian.PutUint64(times[16:], uint64(src.Atimespec.Sec))
	binary.LittleEndian.PutUint64(times[24:], uint64(src.Atimespec.Nsec))
	list := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_MODTIME | unix.ATTR_CMN_ACCTIME}
	if err := unix.Setattrlist(fmt.Sprintf("/dev/fd/%d", target.Fd()), &list, times[:], 0); err != nil {
		return err
	}
	return unix.Fchflags(int(target.Fd()), int(src.Flags & ^uint32(omitted)))
}
