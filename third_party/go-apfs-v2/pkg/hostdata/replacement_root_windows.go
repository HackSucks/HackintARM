package hostdata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	reopenFile  = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")
	backupRead  = windows.NewLazySystemDLL("kernel32.dll").NewProc("BackupRead")
	backupWrite = windows.NewLazySystemDLL("kernel32.dll").NewProc("BackupWrite")
)

// ReOpenFile adds access to an already opened object without resolving its name.
// It also gives BackupRead/Write synchronous handles and independent file offsets.
func reopenReplacementFile(f *os.File, access uint32) (*os.File, error) {
	return reopenReplacementFileSharing(f, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
}
func reopenReplacementFileSharing(file *os.File, access, share uint32) (opened *os.File, err error) {
	err = replacementFileControl(file, func(handle windows.Handle) error {
		h, _, native := reopenFile.Call(uintptr(handle), uintptr(access), uintptr(share), 0)
		if windows.Handle(h) == windows.InvalidHandle {
			return native
		}
		opened = os.NewFile(h, file.Name())
		return nil
	})
	return opened, err
}

type replacementBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	Attributes                                              uint32
	_                                                       uint32
}

func replacementBasic(f *os.File) (replacementBasicInfo, error) {
	var basic replacementBasicInfo
	err := windows.GetFileInformationByHandleEx(windows.Handle(f.Fd()), windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic)))
	return basic, err
}

func prepareReplacementAtContext(ctx context.Context, source *os.File, stage *os.Root, info os.FileInfo) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	basic, err := replacementValue(ctx, func() (replacementBasicInfo, error) { return replacementBasic(source) })
	if err != nil {
		return nil, err
	}
	if basic.Attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, fmt.Errorf("%w: reparse source", ErrUnsupportedReplacement)
	}
	if basic.Attributes&windows.FILE_ATTRIBUTE_ENCRYPTED == 0 {
		// BackupRead/Write retain sparse alternate streams and EAs through held
		// capabilities. CopyFileEx can materialize those sparse streams.
		return prepareReplacementStreamsAtContext(ctx, source, stage, info)
	}
	// Microsoft excludes EFS from BackupRead. Preserve its encrypted streams and
	// key sets with the contained, identity-checked native copy operation.
	file, err := copyReplacementWindows(ctx, source, stage, runReplacementCopy)
	if err != nil {
		return file, err
	}
	if err = copyReplacementEAs(ctx, source, file); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err = initializeReplacementData(ctx, source, file, basic); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil

}

func prepareReplacementStreamsAtContext(ctx context.Context, source *os.File, stage *os.Root, _ os.FileInfo) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	basic, err := replacementValue(ctx, func() (replacementBasicInfo, error) { return replacementBasic(source) })
	if err != nil {
		return nil, err
	}
	if basic.Attributes&(windows.FILE_ATTRIBUTE_ENCRYPTED|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return nil, fmt.Errorf("%w: encrypted or reparse backup source", ErrUnsupportedReplacement)
	}
	f, err := stage.OpenFile("replacement", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	target, err := reopenReplacementFile(f, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_DAC|windows.WRITE_OWNER)
	closeErr := f.Close()
	if err != nil {
		return nil, errors.Join(err, closeErr)
	}
	if closeErr != nil {
		return nil, errors.Join(closeErr, target.Close())
	}
	if err := copyReplacementStreamsContext(ctx, source, target); err != nil {
		return nil, errors.Join(err, target.Close())
	}
	if err := initializeReplacementData(ctx, source, target, basic); err != nil {
		return nil, errors.Join(err, target.Close())
	}
	return target, nil
}

func initializeReplacementData(ctx context.Context, source, target *os.File, basic replacementBasicInfo) error {
	if basic.Attributes&windows.FILE_ATTRIBUTE_SPARSE_FILE != 0 {
		var returned uint32
		if err := replacementStep(ctx, func() error {
			return windows.DeviceIoControl(windows.Handle(target.Fd()), windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &returned, nil)
		}); err != nil {
			return err
		}
	}
	if err := replacementStep(ctx, func() error { return target.Truncate(0) }); err != nil {
		return err
	}
	return copyReplacementCompression(ctx, source, target)
}

func restoreReplacementMetadataAtContext(ctx context.Context, source, target *os.File, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := restoreReplacementMetadataContext(ctx, source, target, info); err != nil {
		return err
	}
	basic, err := replacementBasic(source)
	if err != nil {
		return err
	}
	// Zero leaves the destination's write/access/change times unchanged. Copy
	// creation time and attributes, including hidden/system/archive/readonly.
	basic.LastAccessTime, basic.LastWriteTime, basic.ChangeTime = 0, 0, 0
	return replacementStep(ctx, func() error {
		return windows.SetFileInformationByHandle(windows.Handle(target.Fd()), windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic)))
	})
}

type replacementBackup struct {
	file  *os.File
	call  func(*os.File, []byte, bool, *uintptr) (uint32, error)
	state uintptr
}

func (b *replacementBackup) transfer(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err := b.call(b.file, p, false, &b.state)
	if err != nil {
		return 0, err
	}
	if n > uint32(len(p)) {
		return 0, fmt.Errorf("invalid backup transfer length")
	}
	return int(n), nil
}

func (b *replacementBackup) Read(p []byte) (int, error) {
	n, err := b.transfer(p)
	if n == 0 && err == nil && len(p) != 0 {
		err = io.EOF
	}
	return n, err
}

func (b *replacementBackup) Write(p []byte) (int, error) {
	n, err := b.transfer(p)
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

func (b *replacementBackup) close() error {
	if b.state == 0 {
		return nil
	}
	_, err := b.call(b.file, nil, true, &b.state)
	return err
}

// WIN32_STREAM_ID is a 20-byte wire header followed by a UTF-16 stream name
// and Size bytes. Copy only EAs and named data streams. In particular, never
// feed BACKUP_LINK or OBJECT_ID to BackupWrite: replacement must detach links
// and must not recreate an identity or resolve a pathname from metadata.
func copyReplacementStreamsContext(ctx context.Context, source, target *os.File) (err error) {
	input, err := reopenReplacementFile(source, windows.GENERIC_READ)
	if err != nil {
		return fmt.Errorf("reopen held replacement stream source: %w", err)
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	r := &replacementBackup{file: input, call: replacementBackupRead}
	w := &replacementBackup{file: target, call: replacementBackupWrite}
	defer func() { err = errors.Join(err, r.close(), w.close()) }()
	return filterReplacementStreamsContext(ctx, r, w)
}

func copyReplacementCompression(ctx context.Context, source, target *os.File) error {
	basic, err := replacementValue(ctx, func() (replacementBasicInfo, error) { return replacementBasic(source) })
	if err != nil {
		return err
	}
	if basic.Attributes&windows.FILE_ATTRIBUTE_COMPRESSED == 0 {
		return nil
	}
	var state uint16
	var returned uint32
	if err := replacementStep(ctx, func() error {
		return windows.DeviceIoControl(windows.Handle(source.Fd()), windows.FSCTL_GET_COMPRESSION, nil, 0, (*byte)(unsafe.Pointer(&state)), 2, &returned, nil)
	}); err != nil {
		return err
	}
	if returned != 2 {
		return fmt.Errorf("invalid native compression state length")
	}
	return replacementStep(ctx, func() error {
		return windows.DeviceIoControl(windows.Handle(target.Fd()), windows.FSCTL_SET_COMPRESSION, (*byte)(unsafe.Pointer(&state)), 2, nil, 0, &returned, nil)
	})
}

func replacementBackupRead(file *os.File, p []byte, abort bool, state *uintptr) (uint32, error) {
	return replacementBackupNative(backupRead, file, p, abort, state)
}
func replacementBackupWrite(file *os.File, p []byte, abort bool, state *uintptr) (uint32, error) {
	return replacementBackupNative(backupWrite, file, p, abort, state)
}
func replacementBackupNative(proc *windows.LazyProc, file *os.File, p []byte, abort bool, state *uintptr) (uint32, error) {
	var n uint32
	var ok uintptr
	var err error
	if abort {
		ok, _, err = proc.Call(0, 0, 0, 0, 1, 0, uintptr(unsafe.Pointer(state)))
	} else {
		ok, _, err = proc.Call(file.Fd(), uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)), uintptr(unsafe.Pointer(&n)), 0, 0, uintptr(unsafe.Pointer(state)))
	}
	runtime.KeepAlive(file)
	runtime.KeepAlive(p)
	runtime.KeepAlive(state)

	if ok == 0 {
		return 0, err
	}
	return n, nil
}
