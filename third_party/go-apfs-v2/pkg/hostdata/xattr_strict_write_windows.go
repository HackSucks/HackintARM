package hostdata

import (
	"encoding/binary"
	"strings"

	"golang.org/x/sys/windows"
)

func windowsXattrWriteName(name string) error {
	if err := windowsXattrName(name); err != nil {
		return err
	}
	// Kernel EAs silently ignore user-mode updates. Do not report such an
	// assignment or removal as a successful user-visible mutation.
	if strings.HasPrefix(strings.ToUpper(name), "$KERNEL.") {
		return windows.ERROR_ACCESS_DENIED
	}
	return nil
}

func setVisibleXattrFD(fd int, name string, value []byte) error {
	if err := windowsXattrWriteName(name); err != nil {
		return err
	}
	if len(value) > 65535 {
		return ErrXattrTooLarge
	}
	handle, err := reopenXattrHandle(windows.Handle(fd), windows.FILE_WRITE_EA)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return assignWindowsXattr(handle, name, value)
}

// Callers validate the name/value bounds before reaching this wire encoder.
// A zero-length value is also the native deletion record used by RemoveXattr.
func assignWindowsXattr(handle windows.Handle, name string, value []byte) error {
	record := make([]byte, 9+len(name)+len(value))
	record[5] = byte(len(name))
	binary.LittleEndian.PutUint16(record[6:], uint16(len(value)))
	copy(record[8:], name)
	copy(record[9+len(name):], value)
	return windows.NtSetEaFile(handle, &windows.IO_STATUS_BLOCK{}, &record[0], uint32(len(record)))
}
