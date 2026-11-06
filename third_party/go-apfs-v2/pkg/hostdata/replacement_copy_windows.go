package hostdata

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errReplacementSourcePathMissing = errors.New("held replacement source has no usable path")

var copyFileExW = windows.NewLazySystemDLL("kernel32.dll").NewProc("CopyFileExW")
var replacementCopyCallbacks = struct {
	sync.Mutex
	next   uintptr
	states map[uintptr]*replacementCopyState
}{states: map[uintptr]*replacementCopyState{}}

type replacementWindowsID struct {
	Volume uint64
	ID     [16]byte
}

func replacementWindowsIdentity(handle windows.Handle) (replacementWindowsID, error) {
	var id replacementWindowsID
	err := windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id)))
	return id, err
}
func replacementHeldIdentity(file *os.File) (id replacementWindowsID, err error) {
	conn, err := file.SyscallConn()
	if err != nil {
		return id, err
	}
	var native error
	err = conn.Control(func(fd uintptr) { id, native = replacementWindowsIdentity(windows.Handle(fd)) })
	return id, errors.Join(err, native)
}

// GetFinalPathNameByHandle supplies a lookup hint, never identity authority.
// Volume GUID names avoid mutable drive-letter mappings on local filesystems.
func replacementFinalPath(ctx context.Context, file *os.File) (string, error) {
	conn, err := file.SyscallConn()
	if err != nil {
		return "", err
	}
	var path string
	var native error
	err = conn.Control(func(fd uintptr) {
		path, native = replacementResolveFinalPath(ctx, func(buffer []uint16, flags uint32) (uint32, error) {
			return windows.GetFinalPathNameByHandle(windows.Handle(fd), &buffer[0], uint32(len(buffer)), flags)
		})
	})
	if err = errors.Join(err, native, ctx.Err()); err != nil {
		return "", err
	}
	return path, nil
}

// Keep the bounded native provider protocol separate from descriptor ownership.
// A provider may require a larger buffer or lack volume GUID paths (UNC shares).
func replacementResolveFinalPath(ctx context.Context, query func([]uint16, uint32) (uint32, error)) (string, error) {
	var native error
	for _, flags := range []uint32{1, 0} {
		buffer := make([]uint16, 256)
		for {
			if native = ctx.Err(); native != nil {
				return "", native
			}
			var n uint32
			n, native = query(buffer, flags)
			if native != nil {
				break
			}
			if n < uint32(len(buffer)) {
				path := windows.UTF16ToString(buffer[:n])
				if flags == 0 && !strings.HasPrefix(strings.ToUpper(path), `\\?\UNC\`) {
					return "", fmt.Errorf("replacement requires a stable volume or UNC path")
				}
				return path, nil
			}
			if n > 32768 {
				return "", fmt.Errorf("replacement path exceeds Windows namespace bounds")
			}
			buffer = make([]uint16, n+1)
		}
		// Retry only the documented unavailable volume form. Other provider errors
		// must not turn into a path resolution through mutable drive-letter mappings.
		if !errors.Is(native, windows.ERROR_PATH_NOT_FOUND) && !errors.Is(native, windows.ERROR_INVALID_PARAMETER) {
			return "", native
		}
	}
	return "", native
}

// A native CopyFileEx source/destination handle is borrowed for the callback.
// Never os.NewFile it directly: its finalizer could close a native-owned handle.
func duplicateReplacementHandle(handle windows.Handle, name string) (*os.File, error) {
	// INVALID_HANDLE_VALUE is also the current-process pseudohandle to
	// DuplicateHandle. Validate a file capability before calling that API.
	if _, err := windows.GetFileType(handle); err != nil {
		return nil, err
	}
	var owned windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), handle, windows.CurrentProcess(), &owned, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(owned), name), nil
}

type replacementCopyState struct {
	ctx         context.Context
	source      replacementWindowsID
	stage       *os.Root
	path        string
	file        *os.File
	security    *os.File
	destination replacementWindowsID
	validated   bool
	err         error
	observe     func(uint32) error // per-call qualification seam; production leaves nil
}

func (s *replacementCopyState) progress(reason uint32, source, destination windows.Handle) uintptr {
	if s.err != nil {
		return 1
	}
	if s.err = s.ctx.Err(); s.err != nil {
		return 1
	}
	id, err := replacementWindowsIdentity(source)
	if err != nil || id != s.source {
		s.err = errors.Join(err, fmt.Errorf("replacement copy source identity changed"))
		return 1
	}
	id, err = replacementWindowsIdentity(destination)
	if err != nil {
		s.err = fmt.Errorf("copy callback: query destination identity: %w", err)
		return 1
	}
	if s.validated {
		if id != s.destination {
			s.err = fmt.Errorf("replacement copy destination identity changed")
			return 1
		}
	} else {
		// Root-relative validation occurs before retaining any destination capability.
		check, e := openReplacementStageMetadata(s.stage)
		if e != nil {
			s.err = fmt.Errorf("copy callback: open contained destination metadata: %w", e)
			return 1
		}
		actual, e := replacementHeldIdentity(check)
		e = errors.Join(e, check.Close())
		if e != nil || actual != id {
			s.err = errors.Join(e, fmt.Errorf("replacement copy escaped private stage"))
			return 1
		}
		held, e := duplicateReplacementHandle(destination, s.path)
		if e != nil {
			s.err = fmt.Errorf("copy callback: duplicate destination handle: %w", e)
			return 1
		}
		// CopyFileEx's destination share mode can prohibit another data handle.
		// Retain its exact capability and acquire only security/attribute access
		// during the callback; those rights do not require shared data-write access.
		security, e := replacementWithHandle(s.ctx, func() (*os.File, error) {
			f, e := reopenReplacementFile(held, windows.READ_CONTROL|windows.WRITE_DAC)
			if e != nil {
				return nil, fmt.Errorf("reopen owner security rights: %w", e)
			}
			return f, nil
		}, func(control *os.File) (*os.File, error) {
			if e := replacementPrivateFileAccess(control); e != nil {
				return nil, fmt.Errorf("grant private destination permissions: %w", e)
			}
			f, e := reopenReplacementFile(control, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES)
			if e != nil {
				return nil, fmt.Errorf("reopen private metadata rights: %w", e)
			}
			return f, nil
		})
		if e != nil {
			s.err = fmt.Errorf("copy callback: acquire destination metadata capability: %w", errors.Join(e, held.Close()))
			return 1
		}
		s.file, s.security, s.destination, s.validated = held, security, id, true

	}
	if s.observe != nil {
		s.err = s.observe(reason)
	}
	s.err = errors.Join(s.err, s.ctx.Err())
	if s.err != nil {
		return 1
	}
	return 0
}
func replacementCopyProgress(reason uint32, source, destination, data uintptr) uintptr {
	replacementCopyCallbacks.Lock()
	state := replacementCopyCallbacks.states[data]
	replacementCopyCallbacks.Unlock()
	if state == nil {
		return 1
	}
	return state.progress(reason, windows.Handle(source), windows.Handle(destination))
}
func runReplacementCopy(source, destination *uint16, state *replacementCopyState) error {
	replacementCopyCallbacks.Lock()
	for {
		replacementCopyCallbacks.next++
		if replacementCopyCallbacks.next != 0 && replacementCopyCallbacks.states[replacementCopyCallbacks.next] == nil {
			break
		}
	}
	id := replacementCopyCallbacks.next
	replacementCopyCallbacks.states[id] = state
	replacementCopyCallbacks.Unlock()
	defer func() {
		replacementCopyCallbacks.Lock()
		delete(replacementCopyCallbacks.states, id)
		replacementCopyCallbacks.Unlock()
	}()
	// FAIL_IF_EXISTS alone can follow an existing dangling destination symlink.
	// COPY_SYMLINK makes every existing destination link a collision instead.
	const flags = uint32(0x1 | 0x800)
	ok, _, err := copyFileExW.Call(uintptr(unsafe.Pointer(source)), uintptr(unsafe.Pointer(destination)), replacementCopyCallback, id, 0, uintptr(flags))
	runtime.KeepAlive(source)
	runtime.KeepAlive(destination)
	if ok == 0 {
		return errors.Join(err, state.err, state.ctx.Err())
	}
	return errors.Join(state.err, state.ctx.Err())
}

// An open regular anchor prevents renaming its containing directory chain on
// Windows. A no-delete-share reopen additionally prevents removing the anchor.
// Keep it until copy and final held identity validation finish; callback-only
// validation cannot prevent creation through a replaced ancestor pathname.
func replacementStageAnchor(stage *os.Root) (*os.File, error) {
	return replacementWithHandle(context.Background(), func() (*os.File, error) {
		return stage.OpenFile("anchor", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	}, func(first *os.File) (*os.File, error) {
		return reopenReplacementFileSharing(first, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	})
}

type replacementWindowsCopy func(*uint16, *uint16, *replacementCopyState) error

func copyReplacementWindows(ctx context.Context, source *os.File, stage *os.Root, copyNative replacementWindowsCopy) (file *os.File, err error) {
	anchor, err := replacementStageAnchor(stage)
	if err != nil {
		return nil, errors.Join(err, cleanupReplacement(func() error { return stage.Remove("anchor") }))
	}
	defer func() {
		err = errors.Join(err, anchor.Close(), cleanupReplacement(func() error { return stage.Remove("anchor") }))
		if err != nil && file != nil {
			err = errors.Join(err, file.Close())
			file = nil
		}
	}()
	sourceID, err := replacementHeldIdentity(source)
	if err != nil {
		return nil, fmt.Errorf("query held replacement source identity: %w", err)
	}
	var sourceInfo windows.ByHandleFileInformation
	if err := replacementFileControl(source, func(handle windows.Handle) error {
		return windows.GetFileInformationByHandle(handle, &sourceInfo)
	}); err != nil {
		return nil, fmt.Errorf("query held replacement source links: %w", err)
	}
	if sourceInfo.NumberOfLinks == 0 {
		// A POSIX-unlinked NTFS handle can report an internal $Deleted path.
		// Its zero held link count, not a pathname permission error, establishes
		// that EFS copying has no usable source name. Prepare before unlinking.
		return nil, errors.Join(errReplacementSourcePathMissing, ctx.Err())
	}
	from, err := replacementFinalPath(ctx, source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(errReplacementSourcePathMissing, err)
		}
		return nil, fmt.Errorf("resolve held replacement source path: %w", err)
	}
	anchored, err := replacementFinalPath(ctx, anchor)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(filepath.Base(anchored), "anchor") {
		return nil, fmt.Errorf("replacement anchor name changed")
	}
	to := filepath.Join(filepath.Dir(anchored), "replacement")
	src, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return nil, err
	}
	dst, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return nil, err
	}
	state := &replacementCopyState{ctx: ctx, source: sourceID, stage: stage, path: to}
	// Keep the already granted metadata capability until the whole operation has
	// succeeded. CopyFileEx may restore a restrictive source DACL/readonly flag
	// after its last callback; cancellation after native completion still needs
	// to discard that file without acquiring new write-attribute permissions.
	defer func() {
		if state.security == nil {
			return
		}
		if err != nil {
			cleanup := replacementCleanupMetadata(stage, state.security)
			if cleanup == nil {
				cleanup = replacementPrivateFileAccess(state.security)
			}
			err = errors.Join(err, cleanupReplacement(func() error { return cleanup }))
		}
		err = errors.Join(err, state.security.Close())
	}()

	err = copyNative(src, dst, state)
	if err != nil && errors.Is(err, os.ErrNotExist) && !state.validated {
		if _, missing := os.Stat(from); errors.Is(missing, os.ErrNotExist) {
			err = errors.Join(errReplacementSourcePathMissing, err)
		}
	}
	if err == nil && !state.validated {
		err = fmt.Errorf("replacement copy omitted identity validation")
	}
	if err != nil {
		if state.file != nil {
			err = errors.Join(err, state.file.Close())
		}
		return nil, err
	}
	// The native copy has closed its original handles. Drop its duplicated data
	// capability before reopening; retaining it can retain the exclusive share mode.
	err = state.file.Close()
	state.file = nil
	if err == nil {
		err = replacementStep(ctx, func() error { return replacementPrivateFileAccess(state.security) })
	}
	if err == nil {
		err = replacementClearReadonly(ctx, state.security)
	}
	if err == nil {
		state.file, err = reopenReplacementFile(state.security, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_DAC|windows.WRITE_OWNER)
	}
	err = errors.Join(err, ctx.Err())
	if err != nil {
		if state.file != nil {
			err = errors.Join(err, state.file.Close())
		}
		return nil, fmt.Errorf("copy completion: acquire writable destination: %w", err)
	}
	// The returned capability must still name the file installed beneath stage.
	check, err := openReplacementStageMetadata(stage)
	if err != nil {
		return nil, errors.Join(err, state.file.Close())
	}
	id, err := replacementHeldIdentity(check)
	err = errors.Join(err, check.Close(), ctx.Err())
	if err != nil || id != state.destination {
		return nil, errors.Join(err, fmt.Errorf("replacement stage identity changed"), state.file.Close())
	}
	if err = replacementVerifyEFS(ctx, source, state.file); err != nil {
		return nil, errors.Join(err, state.file.Close())
	}
	return state.file, nil
}

func openReplacementStageMetadata(stage *os.Root) (*os.File, error) {
	file, err := replacementWithHandle(context.Background(), func() (*os.File, error) {
		return stage.Open(".")
	}, func(directory *os.File) (*os.File, error) {
		return openWindowsMetadataRights(directory, "replacement", windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES)
	})
	return file, replacementWindowsError(err)
}

// Normalize each native cause independently. A sole missing name may be ignored
// during private cleanup, but a simultaneous handle/close failure must survive.
func replacementWindowsError(err error) error {
	if status, ok := err.(windows.NTStatus); ok {
		return status.Errno()
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		if len(causes) == 1 {
			return replacementWindowsError(causes[0])
		}
		normalized := make([]error, len(causes))
		for i, cause := range causes {
			normalized[i] = replacementWindowsError(cause)
		}
		return errors.Join(normalized...)
	}
	return err
}

func replacementPrivateFileAccess(file *os.File) error {
	sd, err := replacementPrivateSecurity()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return replacementFileControl(file, func(handle windows.Handle) error {
		return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	})
}

func replacementClearReadonly(ctx context.Context, file *os.File) error {
	basic, err := replacementValue(ctx, func() (replacementBasicInfo, error) { return replacementBasic(file) })
	if err != nil {
		return err
	}
	if basic.Attributes&windows.FILE_ATTRIBUTE_READONLY == 0 {
		return nil
	}
	basic.CreationTime, basic.LastAccessTime, basic.LastWriteTime, basic.ChangeTime = 0, 0, 0, 0
	basic.Attributes &^= windows.FILE_ATTRIBUTE_READONLY
	if basic.Attributes == 0 {
		basic.Attributes = windows.FILE_ATTRIBUTE_NORMAL
	}
	return replacementStep(ctx, func() error {
		return windows.SetFileInformationByHandle(windows.Handle(file.Fd()), windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic)))
	})
}
