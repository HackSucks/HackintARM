package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// Payload descriptors stay open across native-compatible failed-PACK unlink and
// captured backing restoration. Share deletion explicitly: os.OpenFile's Windows
// sharing mode excludes it, which otherwise makes those lifecycle steps fail.
func openPathOrdinary(name string, flags int, mode os.FileMode) (*os.File, error) {
	return openPathWindows(name, flags, mode, windows.CreateFile)
}

type pathWindowsCreate func(*uint16, uint32, uint32, *windows.SecurityAttributes, uint32, uint32, windows.Handle) (windows.Handle, error)

func openPathWindows(name string, flags int, mode os.FileMode, create pathWindowsCreate) (*os.File, error) {
	if name == "" {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.ENOENT}
	}
	full, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	// Win32 device names (including NUL) retain their normal interpretation.
	// Extended paths are necessary only for long filesystem paths.
	if len(full) >= 248 && !strings.HasPrefix(full, `\\?\`) && !strings.HasPrefix(full, `\\.\`) {
		if strings.HasPrefix(full, `\\`) {
			full = `\\?\UNC\` + full[2:]
		} else {
			full = `\\?\` + full
		}
	}
	ptr, err := windows.UTF16PtrFromString(full)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	access := uint32(windows.GENERIC_READ)
	if flags&os.O_RDWR != 0 {
		access |= windows.GENERIC_WRITE
	} else if flags&os.O_WRONLY != 0 {
		access = windows.GENERIC_WRITE
	}
	if flags&os.O_CREATE != 0 {
		access |= windows.GENERIC_WRITE
	}
	if flags&os.O_APPEND != 0 {
		if flags&os.O_TRUNC == 0 {
			access &^= windows.GENERIC_WRITE
		}
		access |= windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA | windows.STANDARD_RIGHTS_WRITE | windows.SYNCHRONIZE
	}
	attrs := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if mode&0200 == 0 {
		attrs = windows.FILE_ATTRIBUTE_READONLY
	}
	if flags&(os.O_WRONLY|os.O_RDWR) == 0 {
		attrs |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	if flags&os.O_SYNC != 0 {
		attrs |= windows.FILE_FLAG_WRITE_THROUGH
	}
	disposition := uint32(windows.OPEN_EXISTING)
	if flags&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL {
		disposition = windows.CREATE_NEW
		attrs |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	} else if flags&os.O_CREATE != 0 {
		disposition = windows.OPEN_ALWAYS
	}
	handle, err := create(ptr, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, disposition, attrs, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) && flags&(os.O_WRONLY|os.O_RDWR) != 0 {
			if info, statErr := os.Stat(name); statErr == nil && info.IsDir() {
				err = syscall.EISDIR
			}
		}
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(handle), name)
	// Truncate the acquired inode, never replace a read-only existing file through
	// CREATE_ALWAYS. Keep acquisition and cleanup errors if truncation fails.
	if flags&os.O_TRUNC != 0 {
		if err := file.Truncate(0); err != nil {
			return nil, errors.Join(err, file.Close())
		}
	}
	return file, nil
}

func chmodPathBacking(file *os.File, mode os.FileMode) error {
	return chmodPathWindowsBacking(file, mode, reopenXattrHandle)
}

func chmodPathWindowsBacking(file *os.File, mode os.FileMode, reopen func(windows.Handle, uint32) (windows.Handle, error)) error {
	return withXattrDescriptor(file, func(fd int) error {
		handle, err := reopen(windows.Handle(fd), windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES)
		if err != nil {
			return err
		}
		metadata := os.NewFile(uintptr(handle), file.Name())
		return errors.Join(metadata.Chmod(mode), metadata.Close())
	})
}
