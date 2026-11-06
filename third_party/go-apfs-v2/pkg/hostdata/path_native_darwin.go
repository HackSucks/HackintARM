package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
	"golang.org/x/sys/unix"
)

type darwinPathABI struct {
	security      *darwinSecurityABI
	stat, lstat   func(*byte, *unix.Stat_t, uintptr) (int32, error)
	chmod         func(*byte, uint32, uint32, int32, uintptr) (int32, error)
	protectedOpen func(*byte, int32, int32, int32, uint32) (int32, error)
}

var loadDarwinPath = func() (*darwinPathABI, error) {
	security, err := loadDarwinSecurity()
	if err != nil {
		return nil, err
	}
	return &darwinPathABI{security: security, stat: darwinabi.Statx, lstat: darwinabi.Lstatx, chmod: darwinabi.ChmodExtended, protectedOpen: darwinabi.OpenDprotected}, nil
}

// CapturePathMetadata obtains identity, size and filesec/stat from one native
// response. It follows intermediate links and optionally the final component;
// callers requiring containment must bind a separately verified held parent.
func CapturePathMetadata(path string, nofollow bool) (PathMetadata, error) {
	a, err := loadDarwinPath()
	if err != nil {
		return PathMetadata{}, err
	}
	return a.capture(path, nofollow)
}

func (a *darwinPathABI) capture(path string, nofollow bool) (result PathMetadata, err error) {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return result, err
	}
	sec := a.security.init()
	if sec == 0 {
		return result, errors.Join(ErrFilesecAllocation, syscall.ENOMEM)
	}
	defer a.security.free(sec)
	stat := a.stat
	if nofollow {
		stat = a.lstat
	}
	var st unix.Stat_t
	if _, err = stat(p, &st, sec); err != nil {
		return result, err
	}
	properties, err := a.security.properties(sec)
	if err != nil {
		return result, err
	}
	result = PathMetadata{State: MetadataState{Security: SecurityCopySource{UID: st.Uid, GID: st.Gid, Mode: uint32(st.Mode), Properties: properties}, Stat: heldStatMetadata(st)}, Identity: LinkIdentity{Device: uint64(st.Dev), Inode: st.Ino, Links: uint64(st.Nlink)}, Size: st.Size}
	return result, nil
}

// WritePathSecurity implements chmodx property translation in Go and invokes
// libSystem's fixed-ABI chmod primitive. Like native chmodx this follows paths;
// it does not claim the containment guarantees of a held descriptor write.
func WritePathSecurity(path string, properties aclmeta.DarwinChmodProperties) error {
	arguments, err := properties.ChmodArguments()
	if err != nil {
		return err
	}
	a, err := loadDarwinPath()
	if err != nil {
		return err
	}
	return a.write(path, arguments)
}

func (a *darwinPathABI) write(path string, arguments aclmeta.DarwinChmodArguments) error {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}
	var security uintptr
	if arguments.SecurityArgument == aclmeta.DarwinSecurityRecord {
		security = uintptr(unsafe.Pointer(unsafe.SliceData(arguments.Security)))
	}
	if arguments.SecurityArgument == aclmeta.DarwinSecurityRemove {
		security = 1
	}
	_, err = a.chmod(p, arguments.UID, arguments.GID, arguments.Mode, security)
	runtime.KeepAlive(arguments.Security)
	return err
}

// PathProtectionSupport checks the named volume, falling back to its parent
// only on ENOENT, matching copyfile's path_does_copy_protection probe. Errors
// remain available to callers; native protected-open treats them as fallback.
func PathProtectionSupport(path string) (bool, error) {
	return pathProtectionSupport(path, unix.Statfs)
}

func pathProtectionSupport(path string, stat func(string, *unix.Statfs_t) error) (bool, error) {
	var st unix.Statfs_t
	err := stat(path, &st)
	if errors.Is(err, unix.ENOENT) {
		err = stat(filepath.Dir(path), &st)
	}
	if err != nil {
		return false, err
	}
	return st.Flags&unix.MNT_CPROTECT != 0, nil
}

// FileProtectionSupport observes content protection from a held descriptor.
// Its errors are fatal inputs to copyfile's creation policy, unlike path probes.
func FileProtectionSupport(file *os.File) (supported bool, err error) {
	err = withXattrDescriptor(file, func(fd int) error {
		var st unix.Statfs_t
		if e := unix.Fstatfs(fd, &st); e != nil {
			return e
		}
		supported = st.Flags&unix.MNT_CPROTECT != 0
		return nil
	})
	return supported, err
}

// ReadProtectionClass queries the class on a native supporting filesystem.
// ENOTSUP and other errors remain observable, never replaced with a default.
func ReadProtectionClass(file *os.File) (class int, err error) {
	err = withXattrDescriptor(file, func(fd int) error {
		var e error
		class, e = unix.FcntlInt(uintptr(fd), unix.F_GETPROTECTIONCLASS, 0)
		return e
	})
	return class, err
}

// SetProtectionClass assigns an explicitly captured class on a held object.
func SetProtectionClass(file *os.File, class int) error {
	return withXattrDescriptor(file, func(fd int) error { _, err := unix.FcntlInt(uintptr(fd), unix.F_SETPROTECTIONCLASS, class); return err })
}

// OpenProtectedPath applies the native path probe's fallback and returns an
// owned descriptor. Ordinary open receives mode; the protected wrapper passes
// it only with O_CREAT. No raw syscall or native copyfile algorithm is used.
func OpenProtectedPath(path string, flags int, protectionClass int, mode uint32) (*os.File, error) {
	return openProtectedPath(path, flags, protectionClass, mode, PathProtectionSupport, unix.Open, loadDarwinPath)
}

func openProtectedPath(path string, flags int, protectionClass int, mode uint32, probe func(string) (bool, error), ordinary func(string, int, uint32) (int, error), load func() (*darwinPathABI, error)) (*os.File, error) {
	supported, probeErr := probe(path)
	if probeErr != nil || !supported {
		fd, err := ordinary(path, flags, mode)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), path), nil
	}
	a, err := load()
	if err != nil {
		return nil, err
	}
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	if flags&unix.O_CREAT == 0 {
		mode = 0
	}
	var fd int32
	fd, err = a.protectedOpen(p, int32(flags), int32(protectionClass), 0, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
