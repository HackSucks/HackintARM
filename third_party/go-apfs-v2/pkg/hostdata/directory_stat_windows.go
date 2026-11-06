package hostdata

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func copyDirectoryStat(source, target *os.File, _, _ os.FileInfo) error {
	from, err := replacementBasic(source)
	if err != nil {
		return err
	}
	to, err := replacementBasic(target)
	if err != nil {
		return err
	}
	const ordinary = windows.FILE_ATTRIBUTE_READONLY | windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_SYSTEM | windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
	const allowed = ordinary | windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_NORMAL
	if from.Attributes & ^uint32(allowed) != 0 || to.Attributes & ^uint32(allowed) != 0 {
		return fmt.Errorf("%w: unsupported Windows directory attributes", ErrUnsupportedDirectoryStat)
	}
	// An empty NT name relative to the held directory opens that object itself.
	// Request directory semantics explicitly, without resolving File.Name.
	name, err := windows.NewNTUnicodeString("")
	if err != nil {
		return err
	}
	attrs := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(target.Fd()), ObjectName: name}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, windows.FILE_WRITE_ATTRIBUTES|windows.SYNCHRONIZE, &attrs, &windows.IO_STATUS_BLOCK{}, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return fmt.Errorf("reopen target directory: %w", err)
	}
	defer windows.CloseHandle(handle)
	basic := replacementBasicInfo{
		LastAccessTime: from.LastAccessTime,
		LastWriteTime:  from.LastWriteTime,
		Attributes:     from.Attributes&ordinary | windows.FILE_ATTRIBUTE_DIRECTORY,
	}
	if err := windows.SetFileInformationByHandle(handle, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return fmt.Errorf("set target directory metadata: %w", err)
	}
	return nil
}
