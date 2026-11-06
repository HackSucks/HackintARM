package hostdata

import (
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openMetadataFile(root *os.Root, name string, _ os.FileInfo) (*os.File, error) {
	return metadataParent(root, name, openWindowsMetadataAt)
}

func openMetadataFileRead(root *os.Root, name string, _ os.FileInfo) (*os.File, error) {
	return metadataParent(root, name, func(parent *os.File, base string) (*os.File, error) {
		return openWindowsMetadataAccess(parent, base, false)
	})
}

func openWindowsMetadataAt(directory *os.File, base string) (*os.File, error) {
	return openWindowsMetadataAccess(directory, base, true)
}

func openWindowsMetadataAccess(directory *os.File, base string, write bool) (*os.File, error) {
	access := uint32(windows.SYNCHRONIZE | windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.FILE_READ_EA)
	if write {
		access |= windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA
	}
	return openWindowsMetadataRights(directory, base, access)
}

func openWindowsMetadataRights(directory *os.File, base string, access uint32) (*os.File, error) {
	if base == "." {
		base = ""
	}
	objectName, err := windows.NewNTUnicodeString(base)
	if err != nil {
		return nil, err
	}
	conn, err := directory.SyscallConn()
	if err != nil {
		return nil, err
	}
	var handle windows.Handle
	var nativeErr error
	controlErr := conn.Control(func(fd uintptr) {
		attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: windows.Handle(fd), ObjectName: objectName, Attributes: windows.OBJ_DONT_REPARSE}
		var status windows.IO_STATUS_BLOCK
		nativeErr = windows.NtCreateFile(&handle, access,
			&attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
			windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	})
	runtime.KeepAlive(objectName)
	if err = errors.Join(controlErr, nativeErr); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), base), nil
}

func openMetadataParent(root *os.Root, name string) (*os.File, error) {
	name, err := metadataParentPath(root, name)
	if err != nil {
		return nil, err
	}
	return root.Open(name)
}
