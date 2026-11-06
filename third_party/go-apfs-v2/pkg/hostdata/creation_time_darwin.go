package hostdata

import (
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func setCreationTime(file *os.File, when time.Time) error {
	a, err := loadDarwinSecurity()
	if err != nil {
		return err
	}
	m := nativeHeldMetadata{file: file, abi: a}
	return m.control(func(fd int32) error {
		stamp := unix.Timespec{Sec: when.Unix(), Nsec: int64(when.Nanosecond())}
		list := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_CRTIME}
		_, err := a.setattr(fd, &list, unsafe.Pointer(&stamp), unsafe.Sizeof(stamp), 0)
		return err
	})
}
