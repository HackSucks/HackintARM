package hostdata

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
	"golang.org/x/sys/unix"
)

type nativeHeldMetadata struct {
	file *os.File
	abi  *darwinSecurityABI
}

func (m *nativeHeldMetadata) DisableCache() error {
	return m.control(func(fd int32) error { _, err := unix.FcntlInt(uintptr(fd), unix.F_NOCACHE, 1); return err })
}

func newHeldMetadata(file *os.File) (heldMetadataOperations, error) {
	conn, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	if err := conn.Control(func(uintptr) {}); err != nil {
		return nil, err
	}
	a, err := loadDarwinSecurity()
	if err != nil {
		return nil, err
	}
	return &nativeHeldMetadata{file: file, abi: a}, nil
}

func (m *nativeHeldMetadata) control(fn func(int32) error) error {
	conn, err := m.file.SyscallConn()
	if err != nil {
		return err
	}
	var callErr error
	if err = conn.Control(func(fd uintptr) { callErr = fn(int32(fd)) }); err != nil {
		return err
	}
	return callErr
}

func (m *nativeHeldMetadata) CaptureSecurity() (result SecurityCopySource, err error) {
	result, _, err = m.CaptureSecurityState()
	return result, err
}

func (m *nativeHeldMetadata) CaptureSecurityState() (result SecurityCopySource, statResult StatCopySource, err error) {
	err = m.control(func(fd int32) error {
		sec := m.abi.init()
		if sec == 0 {
			return errors.Join(ErrFilesecAllocation, syscall.ENOMEM)
		}
		defer m.abi.free(sec)
		var stat unix.Stat_t
		_, err := m.abi.stat(fd, &stat, sec)
		result.UID, result.GID, result.Mode = stat.Uid, stat.Gid, uint32(stat.Mode)
		statResult = heldStatMetadata(stat)
		if err != nil {
			return err
		}
		result.Properties, err = m.abi.properties(sec)
		return err
	})
	if errors.Is(err, syscall.ENOTSUP) {
		err = errors.Join(ErrSecuritySourceNotSupported, err)
	}
	if errors.Is(err, syscall.EPERM) {
		err = errors.Join(ErrSecuritySourceNotPermitted, err)
	}
	return result, statResult, err
}

func (m *nativeHeldMetadata) CaptureStat() (result StatCopySource, err error) {
	err = m.control(func(fd int32) error {
		var stat unix.Stat_t
		if err := unix.Fstat(int(fd), &stat); err != nil {
			return err
		}
		result = heldStatMetadata(stat)
		return nil
	})
	return result, err
}

func heldStatMetadata(stat unix.Stat_t) StatCopySource {
	return StatCopySource{UID: stat.Uid, GID: stat.Gid, Mode: uint32(stat.Mode), Flags: stat.Flags, Times: FileTimes{Birth: time.Unix(stat.Btim.Sec, stat.Btim.Nsec), Modify: time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec), Change: time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec), Access: time.Unix(stat.Atim.Sec, stat.Atim.Nsec)}}
}
func (m *nativeHeldMetadata) CaptureACL() (aclmeta.ACLMetadata, error) {
	s, err := m.CaptureSecurity()
	return metadataACL(s), err
}
func (m *nativeHeldMetadata) CaptureDestinationACL() (*appledouble.ACL, error) {
	a, err := m.CaptureACL()
	return a.Security.ACL, err
}
func (m *nativeHeldMetadata) WriteACL(a aclmeta.ACLMetadata) error {
	r, err := a.DarwinChmodRequest()
	if err != nil {
		return err
	}
	return m.WriteSecurity(aclmeta.DarwinChmodArguments{UID: r.UID, GID: r.GID, Mode: int32(r.Mode), SecurityArgument: aclmeta.DarwinSecurityRecord, Security: r.Security})
}
func (m *nativeHeldMetadata) WriteSecurity(a aclmeta.DarwinChmodArguments) error {
	if err := validateMetadataArguments(a); err != nil {
		return err
	}
	err := m.control(func(fd int32) error {
		var security uintptr
		if a.SecurityArgument == aclmeta.DarwinSecurityRecord {
			security = uintptr(unsafe.Pointer(unsafe.SliceData(a.Security)))
		}
		if a.SecurityArgument == aclmeta.DarwinSecurityRemove {
			security = 1
		}
		_, err := m.abi.chmod(fd, a.UID, a.GID, a.Mode, security)
		runtime.KeepAlive(a.Security)
		return err
	})
	if errors.Is(err, syscall.ENOTSUP) {
		return errors.Join(errors.ErrUnsupported, err)
	}
	return err
}
func (m *nativeHeldMetadata) SetACL(acl *appledouble.ACL) error {
	p := aclmeta.DarwinChmodProperties{RemoveACL: acl == nil}
	if acl != nil {
		p.RawSecurity = &appledouble.FileSecurity{ACL: acl}
	}
	a, err := p.ChmodArguments()
	if err != nil {
		return err
	}
	return m.WriteSecurity(a)
}
func (m *nativeHeldMetadata) Chmod(mode uint16) error {
	return m.control(func(fd int32) error { return unix.Fchmod(int(fd), uint32(mode)) })
}
func (m *nativeHeldMetadata) Chown(uid, gid uint32) error {
	return m.control(func(fd int32) error { return unix.Fchown(int(fd), int(int32(uid)), int(int32(gid))) })
}
func (m *nativeHeldMetadata) SetTimes(modify, access time.Time) error {
	return setHeldFileTimes(m, modify, access)
}

func setFileTimes(file *os.File, modify, access time.Time) error {
	a, err := loadDarwinSecurity()
	if err != nil {
		return err
	}
	return setHeldFileTimes(&nativeHeldMetadata{file: file, abi: a}, modify, access)
}

func setHeldFileTimes(m *nativeHeldMetadata, modify, access time.Time) error {
	return m.control(func(fd int32) error {
		list := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_MODTIME | unix.ATTR_CMN_ACCTIME}
		times := [2]unix.Timespec{{Sec: modify.Unix(), Nsec: int64(modify.Nanosecond())}, {Sec: access.Unix(), Nsec: int64(access.Nanosecond())}}
		_, err := m.abi.setattr(fd, &list, unsafe.Pointer(&times), unsafe.Sizeof(times), 0)
		runtime.KeepAlive(times)
		return err
	})
}
func (m *nativeHeldMetadata) ReadFlags() (uint32, error) {
	stat, err := m.CaptureStat()
	return stat.Flags, err
}
func (m *nativeHeldMetadata) CompareAndSwapFlags(expected, replacement uint32) (actual uint32, err error) {
	args := [3]uint32{expected, replacement, 0}
	err = m.control(func(fd int32) error {
		_, err := m.abi.fsctl(fd, 0xc00c4114, unsafe.Pointer(&args), 0)
		return err
	})
	if errors.Is(err, syscall.EAGAIN) {
		err = errors.Join(ErrStatFlagsAgain, err)
	}
	return args[2], err
}
func (m *nativeHeldMetadata) Chflags(flags uint32) error {
	return m.control(func(fd int32) error { return unix.Fchflags(int(fd), int(flags)) })
}
