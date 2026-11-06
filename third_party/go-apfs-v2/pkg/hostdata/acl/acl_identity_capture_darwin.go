package acl

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type darwinPasswd = darwinabi.Passwd
type darwinGroup = darwinabi.Group

type darwinIdentityABI struct {
	userID              func(uint32, *darwinPasswd, *byte, uintptr, **darwinPasswd) int32
	userName            func(*byte, *darwinPasswd, *byte, uintptr, **darwinPasswd) int32
	groupID             func(uint32, *darwinGroup, *byte, uintptr, **darwinGroup) int32
	groupName           func(*byte, *darwinGroup, *byte, uintptr, **darwinGroup) int32
	userUUID, groupUUID func(uint32, *[16]byte) int32
	uuidID              func(*[16]byte, *uint32, *int32) int32
}

var loadDarwinIdentity = func() (*darwinIdentityABI, error) {
	return &darwinIdentityABI{userID: darwinabi.Getpwuid, userName: darwinabi.Getpwnam, groupID: darwinabi.Getgrgid, groupName: darwinabi.Getgrnam, userUUID: darwinabi.UserUUID, groupUUID: darwinabi.GroupUUID, uuidID: darwinabi.UUIDIdentity}, nil
}

func newNativeACLIdentityCapture(ctx context.Context, limit int) (*appledouble.ACLIdentityCapture, error) {
	a, err := loadDarwinIdentity()
	if err != nil {
		return nil, err
	}
	return identityCaptureWithABI(ctx, limit, a), nil
}

func identityCaptureWithABI(ctx context.Context, limit int, a *darwinIdentityABI) *appledouble.ACLIdentityCapture {
	resolve := func(identity appledouble.ACLIdentity) ([16]byte, error) {
		account, found, err := a.account(ctx, identity, limit)
		if err != nil || !found {
			return [16]byte{}, err
		}
		convert := a.userUUID
		if identity.Group {
			convert = a.groupUUID
		}
		var uuid [16]byte
		if code := convert(account.ID, &uuid); code != 0 {
			return [16]byte{}, syscall.Errno(code)
		}
		if err := ctx.Err(); err != nil {
			return [16]byte{}, err
		}
		return uuid, nil
	}
	lookup := func(uuid [16]byte) (appledouble.ACLPrincipal, bool, error) {
		if err := ctx.Err(); err != nil {
			return appledouble.ACLPrincipal{}, false, err
		}
		var id uint32
		var kind int32
		code := a.uuidID(&uuid, &id, &kind)
		if err := ctx.Err(); err != nil {
			return appledouble.ACLPrincipal{}, false, err
		}
		if code == int32(syscall.ENOENT) {
			return appledouble.ACLPrincipal{}, false, nil
		}
		if code != 0 {
			return appledouble.ACLPrincipal{}, false, syscall.Errno(code)
		}
		if kind != 0 && kind != 1 {
			return appledouble.ACLPrincipal{}, false, appledouble.ErrACLResolver
		}
		return a.account(ctx, appledouble.ACLIdentity{Group: kind == 1, ID: &id}, limit)
	}
	return appledouble.NewACLIdentityCapture(resolve, lookup)
}

func (a *darwinIdentityABI) account(ctx context.Context, identity appledouble.ACLIdentity, limit int) (appledouble.ACLPrincipal, bool, error) {
	if (identity.ID == nil) == (identity.Name == "") {
		return appledouble.ACLPrincipal{}, false, os.ErrInvalid
	}
	var name *byte
	if identity.ID == nil {
		var err error
		name, err = syscall.BytePtrFromString(identity.Name)
		if err != nil {
			return appledouble.ACLPrincipal{}, false, err
		}
	}
	for size := min(4096, limit); ; size = nextIdentitySize(size, limit) {
		if err := ctx.Err(); err != nil {
			return appledouble.ACLPrincipal{}, false, err
		}
		buffer := make([]byte, size)
		principal, found, code, err := a.accountRecord(identity, name, buffer)
		runtime.KeepAlive(name)
		if err != nil {
			return appledouble.ACLPrincipal{}, false, err
		}
		if err := ctx.Err(); err != nil {
			return appledouble.ACLPrincipal{}, false, err
		}
		if code == int32(syscall.ERANGE) {
			if size == limit {
				return appledouble.ACLPrincipal{}, false, ErrACLIdentityLimit
			}
			continue
		}
		if code != 0 {
			return appledouble.ACLPrincipal{}, false, syscall.Errno(code)
		}
		return principal, found, nil
	}
}

func (a *darwinIdentityABI) accountRecord(identity appledouble.ACLIdentity, name *byte, buffer []byte) (appledouble.ACLPrincipal, bool, int32, error) {
	var code int32
	var resultName *byte
	var id uint32
	if identity.Group {
		var record darwinGroup
		var result *darwinGroup
		if identity.ID != nil {
			code = a.groupID(*identity.ID, &record, unsafe.SliceData(buffer), uintptr(len(buffer)), &result)
		} else {
			code = a.groupName(name, &record, unsafe.SliceData(buffer), uintptr(len(buffer)), &result)
		}
		if code != 0 || result == nil {
			return appledouble.ACLPrincipal{}, false, code, nil
		}
		if result != &record {
			return appledouble.ACLPrincipal{}, false, 0, appledouble.ErrACLResolver
		}
		resultName, id = record.Name, record.GID
	} else {
		var record darwinPasswd
		var result *darwinPasswd
		if identity.ID != nil {
			code = a.userID(*identity.ID, &record, unsafe.SliceData(buffer), uintptr(len(buffer)), &result)
		} else {
			code = a.userName(name, &record, unsafe.SliceData(buffer), uintptr(len(buffer)), &result)
		}
		if code != 0 || result == nil {
			return appledouble.ACLPrincipal{}, false, code, nil
		}
		if result != &record {
			return appledouble.ACLPrincipal{}, false, 0, appledouble.ErrACLResolver
		}
		resultName, id = record.Name, record.UID
	}
	text, err := identityName(buffer, resultName)
	runtime.KeepAlive(buffer)
	if err != nil {
		return appledouble.ACLPrincipal{}, false, 0, err
	}
	return appledouble.ACLPrincipal{Group: identity.Group, Name: text, ID: id}, true, 0, nil
}

func identityName(buffer []byte, name *byte) (string, error) {
	start, ptr := uintptr(unsafe.Pointer(unsafe.SliceData(buffer))), uintptr(unsafe.Pointer(name))
	if name == nil || ptr < start || ptr-start >= uintptr(len(buffer)) {
		return "", appledouble.ErrACLResolver
	}
	b := buffer[ptr-start:]
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		return "", appledouble.ErrACLResolver
	}
	return string(b[:n]), nil
}

func nextIdentitySize(size, limit int) int { return size + min(size, limit-size) }
