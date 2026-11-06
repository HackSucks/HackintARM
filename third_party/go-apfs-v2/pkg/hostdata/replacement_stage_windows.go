package hostdata

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"
)

type replacementPlatformState struct {
	rooted    *RootReplacement
	ownedRoot *os.Root
}

func replacementPrivateSecurity() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)")
}

// Install the private DACL in the atomic creation operation. Applying it after
// Mkdir would leave a window in which another principal could retain a handle.
// Keep the no-delete-share creation handle through native copy completion.
func makeReplacementDirectoryAt(ctx context.Context, root *os.Root, name string) (release func() error, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	parent, err := root.Open(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, parent.Close())
	}()
	sd, err := replacementPrivateSecurity()
	if err != nil {
		return nil, err
	}
	object, err := windows.NewNTUnicodeString(filepath.Base(name))
	if err != nil {
		return nil, err
	}
	conn, err := parent.SyscallConn()
	if err != nil {
		return nil, err
	}
	var handle windows.Handle
	var native error
	control := conn.Control(func(fd uintptr) {
		attrs := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: windows.Handle(fd), ObjectName: object, Attributes: windows.OBJ_DONT_REPARSE, SecurityDescriptor: sd}
		native = windows.NtCreateFile(&handle, windows.GENERIC_READ|windows.SYNCHRONIZE, &attrs, &windows.IO_STATUS_BLOCK{}, nil, windows.FILE_ATTRIBUTE_DIRECTORY, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	})
	runtime.KeepAlive(sd)
	runtime.KeepAlive(object)
	if err = errors.Join(control, replacementWindowsError(native)); err != nil {
		return nil, err
	}
	held := os.NewFile(uintptr(handle), name)
	release = held.Close
	if err = ctx.Err(); err != nil {
		return release, err
	}
	return release, nil
}

func prepareReplacementPrivateContext(ctx context.Context, source *os.File, parent string, _ os.FileInfo, options ReplacementOptions) (*Replacement, error) {
	if parent == "" {
		parent = os.TempDir()
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	staged, err := PrepareReplacementAtWithOptionsContext(ctx, source, root, ".", options)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return &Replacement{File: staged.File, replacementPlatformState: replacementPlatformState{rooted: staged, ownedRoot: root}}, nil
}

// Retain the already granted attribute rights until Close, even if the caller
// closes File after restoring an ACL which denies new write-attribute opens.
func replacementCleanupCapability(file *os.File) (owned *os.File, err error) {
	conn, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	var native error
	err = conn.Control(func(fd uintptr) { owned, native = duplicateReplacementHandle(windows.Handle(fd), file.Name()) })
	return owned, errors.Join(err, native)
}
func replacementCleanupMetadata(stage *os.Root, held *os.File) error {
	if held == nil {
		return stage.Chmod("replacement", 0600)
	}
	named, err := openReplacementStageMetadata(stage)
	if err != nil {
		return err
	}
	expected, err := replacementHeldIdentity(held)
	actual, lookupErr := replacementHeldIdentity(named)
	err = errors.Join(err, lookupErr, named.Close())
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("private replacement identity changed before cleanup")
	}
	return replacementClearReadonly(context.Background(), held)
}

func restorePrivateReplacementContext(ctx context.Context, r *Replacement) error {
	return r.rooted.RestoreMetadataContext(ctx)
}
func closePrivateReplacement(r *Replacement) error {
	err := r.rooted.Close()
	if r.ownedRoot != nil {
		err = errors.Join(err, r.ownedRoot.Close())
		r.ownedRoot = nil
	}
	return err
}

func preparePrivateFilesystemReplacement(ctx context.Context, r *Replacement, _ *os.File, _ ReplacementOptions) error {
	r.filesystem = r.rooted.filesystem
	return ctx.Err()
}
