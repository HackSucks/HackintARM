package hostdata

import (
	"errors"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"
	"golang.org/x/sys/unix"
	"os"
	"unsafe"
)

func readEntryType(root *os.Root, name string) (mode os.FileMode, err error) {
	_, err = metadataParent(root, name, func(parent *os.File, base string) (*os.File, error) {
		mode, err = entryTypeAt(parent, base)
		return nil, err
	})
	return mode, err
}

func entryTypeAt(parent *os.File, base string) (os.FileMode, error) {
	name, err := unix.BytePtrFromString(base)
	if err != nil {
		return 0, err
	}
	conn, err := parent.SyscallConn()
	if err != nil {
		return 0, err
	}
	attrs := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_OBJTYPE}
	var data [2]uint32
	var queryErr error
	err = conn.Control(func(fd uintptr) {
		_, queryErr = darwinabi.Getattrlistat(int32(fd), name, &attrs, unsafe.Pointer(&data), unsafe.Sizeof(data), unix.FSOPT_NOFOLLOW)
	})
	if err = errors.Join(err, queryErr); err != nil {
		return 0, err
	}
	return decodeEntryType(data)
}

func decodeEntryType(data [2]uint32) (os.FileMode, error) {
	if data[0] != 8 {
		return 0, fmt.Errorf("entry type attribute length %d: %w", data[0], os.ErrInvalid)
	}
	// ATTR_CMN_OBJTYPE is enum vtype, not POSIX st_mode.
	switch data[1] {
	case 1:
		return 0, nil
	case 2:
		return os.ModeDir, nil
	case 3:
		return os.ModeDevice, nil
	case 4:
		return os.ModeDevice | os.ModeCharDevice, nil
	case 5:
		return os.ModeSymlink, nil
	case 6:
		return os.ModeSocket, nil
	case 7:
		return os.ModeNamedPipe, nil
	default:
		return 0, fmt.Errorf("vnode type %d: %w", data[1], errors.ErrUnsupported)
	}
}
