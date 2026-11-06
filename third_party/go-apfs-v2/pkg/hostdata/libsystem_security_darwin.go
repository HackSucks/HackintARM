package hostdata

import (
	"errors"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
	"golang.org/x/sys/unix"
)

// Only libSystem IO and filesec property access cross this boundary. The ACL,
// AppleDouble, policy and ordering algorithms remain Go implementations.
type darwinSecurityABI struct {
	init    func() uintptr
	free    func(uintptr)
	get     func(uintptr, int32, unsafe.Pointer) (int32, error)
	stat    func(int32, *unix.Stat_t, uintptr) (int32, error)
	chmod   func(int32, uint32, uint32, int32, uintptr) (int32, error)
	setattr func(int32, *unix.Attrlist, unsafe.Pointer, uintptr, uint32) (int32, error)
	fsctl   func(int32, uintptr, unsafe.Pointer, uint32) (int32, error)
}

var loadDarwinSecurity = func() (*darwinSecurityABI, error) {
	return &darwinSecurityABI{init: darwinabi.FilesecInit, free: darwinabi.FilesecFree, get: darwinabi.FilesecGetProperty, stat: darwinabi.Fstatx, chmod: darwinabi.FchmodExtended, setattr: darwinabi.Fsetattrlist, fsctl: darwinabi.Ffsctl}, nil
}

func (a *darwinSecurityABI) property(sec uintptr, name int32, out unsafe.Pointer) (bool, error) {
	_, err := a.get(sec, name, out)
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	return err == nil, err
}

func (a *darwinSecurityABI) properties(sec uintptr) (result aclmeta.DarwinChmodProperties, err error) {
	for _, item := range []struct {
		name   int32
		target **uint32
	}{{1, &result.UID}, {2, &result.GID}} {
		var value uint32
		present, e := a.property(sec, item.name, unsafe.Pointer(&value))
		if e != nil {
			return result, e
		}
		if present {
			*item.target = &value
		}
	}
	var mode uint16
	present, err := a.property(sec, 4, unsafe.Pointer(&mode))
	if err != nil {
		return result, err
	}
	if present {
		value := uint32(mode)
		result.Mode = &value
	}
	for _, item := range []struct {
		name   int32
		target **[16]byte
	}{{3, &result.OwnerUUID}, {6, &result.GroupUUID}} {
		var value [16]byte
		present, e := a.property(sec, item.name, unsafe.Pointer(&value))
		if e != nil {
			return result, e
		}
		if present {
			*item.target = &value
		}
	}
	var raw unsafe.Pointer
	present, err = a.property(sec, 100, unsafe.Pointer(&raw))
	if err != nil || !present {
		return result, err
	}
	var size uintptr
	present, err = a.property(sec, 101, unsafe.Pointer(&size))
	if err != nil {
		return result, err
	}
	if !present || raw == nil || !SecurityRecordSizeValid(uint64(size)) {
		return result, appledouble.ErrFileSecurity
	}
	result.RawSecurity, err = appledouble.ParseDarwinFileSecurity(unsafe.Slice((*byte)(raw), int(size)))
	if err == nil {
		result.RawSecurity.Trailing = nil
	}
	return result, err
}
