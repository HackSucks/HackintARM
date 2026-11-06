package hostdata

import (
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const missingXattrError = windows.STATUS_NONEXISTENT_EA_ENTRY

func windowsXattrName(name string) error {
	if len(name) == 0 || len(name) >= 255 || strings.ContainsAny(name, `\/:*?"<>|,+=[];`) {
		return os.ErrInvalid
	}
	for _, c := range []byte(name) {
		if c < 32 || c > 126 {
			return os.ErrInvalid
		}
	}
	return nil
}

// Reopen the held object itself for synchronous EA I/O. The empty NT name
// cannot be redirected by renaming File.Name. OPEN_REPARSE_POINT retains a
// caller-held link. Windows checks access without backup privilege/intent.
func reopenXattrHandle(handle windows.Handle, access uint32) (windows.Handle, error) {
	name, _ := windows.NewNTUnicodeString("")
	attrs := windows.OBJECT_ATTRIBUTES{RootDirectory: handle, ObjectName: name}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var result windows.Handle
	err := windows.NtCreateFile(&result, access|windows.SYNCHRONIZE, &attrs, &windows.IO_STATUS_BLOCK{}, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	return result, err
}

func openXattrPath(path string, access uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, access|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func getVisibleXattrFD(fd int, name string, buf []byte) (int, error) {
	handle, err := reopenXattrHandle(windows.Handle(fd), windows.FILE_READ_EA)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)
	return queryWindowsXattr(handle, name, buf)
}

func getVisibleXattrPath(path, name string, buf []byte) (int, error) {
	handle, err := openXattrPath(path, windows.FILE_READ_EA)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)
	return queryWindowsXattr(handle, name, buf)
}

func queryWindowsXattr(handle windows.Handle, name string, buf []byte) (int, error) {
	if err := windowsXattrName(name); err != nil {
		return 0, err
	}
	// FILE_GET_EA_INFORMATION: next offset, name length, name and NUL.
	query := make([]byte, 6+len(name))
	query[4] = byte(len(name))
	copy(query[5:], name)
	record := make([]byte, strictWindowsEABufferSize)
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtQueryEaFile(handle, &status, &record[0], uint32(len(record)), true, &query[0], uint32(len(query)), nil, true); err != nil {
		return 0, err
	}
	if status.Information > uintptr(len(record)) {
		return 0, windows.STATUS_EA_CORRUPT_ERROR
	}
	return decodeWindowsXattr(record[:status.Information], name, buf)
}

func decodeWindowsXattr(record []byte, name string, buf []byte) (int, error) {
	actual, value, err := parseXattrEA(record)
	if err != nil || !strings.EqualFold(actual, name) {
		return 0, windows.STATUS_EA_CORRUPT_ERROR
	}
	size := len(value)
	// A named query may return an empty record for an absent EA. NTFS deletes
	// zero-length values: it cannot retain a present-empty extended attribute.
	if size == 0 {
		return 0, windows.STATUS_NONEXISTENT_EA_ENTRY
	}
	if buf != nil {
		if size > len(buf) {
			return 0, windows.STATUS_BUFFER_TOO_SMALL
		}
		copy(buf, value)
	}
	return size, nil
}

func removeVisibleXattrFD(fd int, name string) error {
	handle, err := reopenXattrHandle(windows.Handle(fd), windows.FILE_READ_EA|windows.FILE_WRITE_EA)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return removeWindowsXattr(handle, name)
}

func removeVisibleXattrPath(path, name string) error {
	handle, err := openXattrPath(path, windows.FILE_READ_EA|windows.FILE_WRITE_EA)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return removeWindowsXattr(handle, name)
}

func removeWindowsXattr(handle windows.Handle, name string) error {
	if err := windowsXattrWriteName(name); err != nil {
		return err
	}
	// Native deletion succeeds even for a missing name. Query this same handle
	// first to preserve removed-versus-absent. Concurrent mutation is not atomic.
	if _, err := queryWindowsXattr(handle, name, nil); err != nil {
		return err
	}
	return assignWindowsXattr(handle, name, nil)
}

func missingXattr(err error) bool {
	return errors.Is(err, windows.STATUS_NO_EAS_ON_FILE) || errors.Is(err, windows.STATUS_NONEXISTENT_EA_ENTRY)
}
func xattrRangeError(err error) bool {
	return errors.Is(err, windows.STATUS_BUFFER_TOO_SMALL) || errors.Is(err, windows.STATUS_BUFFER_OVERFLOW)
}
func strictXattrError(err error) error {
	if errors.Is(err, windows.STATUS_EAS_NOT_SUPPORTED) || errors.Is(err, windows.STATUS_NOT_SUPPORTED) || errors.Is(err, windows.STATUS_INVALID_DEVICE_REQUEST) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
		return errors.Join(ErrXattrUnsupported, err)
	}
	return err
}
