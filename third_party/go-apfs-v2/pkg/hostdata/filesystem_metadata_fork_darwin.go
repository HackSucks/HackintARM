package hostdata

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FAT named-fork vnodes need not share their data vnode's inode number. Use
// held fgetxattr for FAT forks instead of weakening OpenResourceFork's identity
// contract. AppleDouble's 32-bit fork length bounds the positional API exactly;
// native APFS/HFS forks continue through the 64-bit named-stream route.
func nativeFilesystemResource(ctx context.Context, file *os.File) (*MetadataValue, error) {
	return nativeFilesystemResourceUsing(ctx, file, func(fd int) (string, error) {
		var stat unix.Statfs_t
		err := unix.Fstatfs(fd, &stat)
		return unix.ByteSliceToString(stat.Fstypename[:]), err
	}, unix.Dup)
}

func nativeFilesystemResourceUsing(ctx context.Context, file *os.File, volume func(int) (string, error), duplicate func(int) (int, error)) (*MetadataValue, error) {
	var owned *os.File
	err := withXattrDescriptor(file, func(fd int) error {
		name, err := volume(fd)
		if err != nil {
			return err
		}
		if name != "exfat" && name != "msdos" {
			return nil
		}
		copy, err := duplicate(fd)
		if err != nil {
			return err
		}
		owned = os.NewFile(uintptr(copy), "filesystem resource fork")
		return nil
	})
	if err != nil || owned == nil {
		return nil, err
	}
	size, present, err := XattrSize(owned, ResourceForkName)
	if err == nil && (!present || size < 0 || uint64(size) > math.MaxUint32) {
		err = ErrXattrChanged
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return nil, errors.Join(err, owned.Close())
	}
	value := &filesystemNativeFork{file: owned, length: int64(size), read: darwinFilesystemForkRead}
	return &MetadataValue{value: value, closer: owned, ctx: ctx}, nil
}

type filesystemNativeFork struct {
	file   *os.File
	length int64
	read   func(int, []byte, uint32) (int, error)
}

func (v *filesystemNativeFork) Size() int64 { return v.length }
func (v *filesystemNativeFork) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, os.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= v.length {
		return 0, io.EOF
	}
	// Check the owned file before using SyscallConn: the latter may return an
	// internal poll error after Close rather than the public os.ErrClosed.
	// Preserve the public file-lifetime error at this reader boundary.
	if _, err := v.file.Stat(); err != nil {
		return 0, err
	}
	size, present, err := XattrSize(v.file, ResourceForkName)
	if err != nil {
		return 0, err
	}
	if !present || int64(size) != v.length {
		return 0, ErrXattrChanged
	}
	count := min(int64(len(p)), v.length-off)
	err = withXattrDescriptor(v.file, func(fd int) error { var e error; n, e = v.read(fd, p[:int(count)], uint32(off)); return e })
	if err == nil && n != int(count) {
		err = ErrXattrChanged
	}
	if err == nil && n < len(p) {
		err = io.EOF
	}
	return
}

func darwinFilesystemForkRead(fd int, p []byte, position uint32) (int, error) {
	name, err := syscall.BytePtrFromString(ResourceForkName)
	if err != nil {
		return 0, err
	}
	abi, err := loadDarwinXattr()
	if err != nil {
		return 0, err
	}
	n, err := darwinSizeResult(abi.getFD(int32(fd), name, unsafe.SliceData(p), uintptr(len(p)), position, 0))
	runtime.KeepAlive(name)
	runtime.KeepAlive(p)
	return n, err
}
