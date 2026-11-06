package hostdata

import (
	"runtime"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"
)

// These fixed signatures come from sys/xattr.h. x/sys does not expose Darwin's
// compression visibility or resource-fork position arguments. libSystem is used
// only for host IO; all AppleDouble policy and encoding remain Go code.
type darwinXattrABI struct {
	listPath func(*byte, *byte, uintptr, int32) (int64, error)
	getPath  func(*byte, *byte, *byte, uintptr, uint32, int32) (int64, error)
	listFD   func(int32, *byte, uintptr, int32) (int64, error)
	getFD    func(int32, *byte, *byte, uintptr, uint32, int32) (int64, error)
}

var loadDarwinXattr = func() (*darwinXattrABI, error) {
	return &darwinXattrABI{listPath: darwinabi.Listxattr, getPath: darwinabi.Getxattr, listFD: darwinabi.Flistxattr, getFD: darwinabi.Fgetxattr}, nil
}

func darwinListXattrPath(path string, buf []byte, flags int32) (int, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	a, err := loadDarwinXattr()
	if err != nil {
		return 0, err
	}
	n, err := darwinSizeResult(a.listPath(p, unsafe.SliceData(buf), uintptr(len(buf)), flags))
	runtime.KeepAlive(p)
	runtime.KeepAlive(buf)
	return n, err
}

func darwinGetXattrPath(path, name string, buf []byte, flags int32) (int, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	q, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	a, err := loadDarwinXattr()
	if err != nil {
		return 0, err
	}
	n, err := darwinSizeResult(a.getPath(p, q, unsafe.SliceData(buf), uintptr(len(buf)), 0, flags))
	runtime.KeepAlive(p)
	runtime.KeepAlive(q)
	runtime.KeepAlive(buf)
	return n, err
}

func listCaptureXattrFD(fd, limit int) ([]string, error) {
	a, err := loadDarwinXattr()
	if err != nil {
		return nil, err
	}
	return readXattrNames(func(buf []byte) (int, error) {
		n, err := darwinSizeResult(a.listFD(int32(fd), unsafe.SliceData(buf), uintptr(len(buf)), xattrShowCompression))
		runtime.KeepAlive(buf)
		return n, err
	}, limit)
}

func getCaptureXattrFD(fd int, name string, buf []byte) (int, error) {
	q, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	a, err := loadDarwinXattr()
	if err != nil {
		return 0, err
	}
	n, err := darwinSizeResult(a.getFD(int32(fd), q, unsafe.SliceData(buf), uintptr(len(buf)), 0, xattrShowCompression))
	runtime.KeepAlive(q)
	runtime.KeepAlive(buf)
	return n, err
}
