package hostdata

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	hostflags "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/bsdflags"
	"golang.org/x/sys/unix"
)

func prepareReplacementContext(ctx context.Context, source *os.File, path string, info os.FileInfo) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	flags, _ := hostflags.Flags(info)
	if flags&(unix.UF_IMMUTABLE|unix.UF_APPEND|unix.SF_IMMUTABLE|unix.SF_APPEND) != 0 {
		return nil, fmt.Errorf("%w: protected source", ErrUnsupportedReplacement)
	}
	// clonefile also applies inherited destination ACLs. The directory is ours:
	// clear its ACL before cloning. Source ACLs are restored after content writes,
	// so deny-write entries cannot prevent opening the private copy for writing.
	// This is kauth_filesec with KAUTH_FILESEC_NOACL (sys/kauth.h), preceded by
	// an attrreference_t (sys/attr.h). Setattrlist is a libSystem wrapper.
	if err := clearReplacementACL(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return prepareReplacementUsingContext(ctx,
		func() error {
			// Rewritten logical contents must not inherit the old compressed
			// storage. A fresh file also avoids decompression writes against
			// a clone before the caller has supplied the replacement bytes.
			if flags&UFCompressed != 0 {
				return unix.ENOTSUP
			}
			return unix.Fclonefileat(int(source.Fd()), unix.AT_FDCWD, path, 0)
		},
		replacementCloneUnavailable,
		func(cloned bool) (*os.File, error) {
			return replacementOpenAfterClone(cloned, func() error { return os.Chmod(path, 0600) }, func(cloned bool) (*os.File, error) {
				flags := os.O_RDWR
				if !cloned {
					flags |= os.O_CREATE | os.O_EXCL
				}
				return os.OpenFile(path, flags, 0600)
			})
		},
		func(target *os.File) error { return copyReplacementMetadataContext(ctx, source, target, info) },
	)
}

func clearReplacementACL(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return clearReplacementHeldACL(file)
}

func clearReplacementHeldACL(file *os.File) error {
	supported, err := replacementVolumeACL(file)
	if err != nil || !supported {
		return err
	}
	acl := make([]byte, 52)
	binary.LittleEndian.PutUint32(acl, 8)
	binary.LittleEndian.PutUint32(acl[4:], 44)
	binary.LittleEndian.PutUint32(acl[8:], 0x012cc16d)
	binary.LittleEndian.PutUint32(acl[44:], 0xffffffff)
	list := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	m := nativeHeldMetadata{file: file}
	return m.control(func(fd int32) error {
		_, err := darwinabi.Fsetattrlist(fd, &list, unsafe.Pointer(&acl[0]), uintptr(len(acl)), 0)
		return err
	})
}

func restoreReplacementMetadataContext(ctx context.Context, source *os.File, target *os.File, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s := info.Sys().(*syscall.Stat_t)
	if err := replacementStep(ctx, func() error { return target.Chown(int(s.Uid), int(s.Gid)) }); err != nil {
		return err
	}
	if err := replacementStep(ctx, func() error { return target.Chmod(info.Mode()) }); err != nil {
		return err
	}
	if err := replacementStep(ctx, func() error { return restoreReplacementACL(source, target) }); err != nil {
		return err
	}
	// Compression describes the target's current storage, not source policy.
	// Never reattach UF_COMPRESSED to the caller's rewritten logical data.
	current, err := replacementValue(ctx, target.Stat)
	if err != nil {
		return err
	}
	targetFlags, _ := hostflags.Flags(current)
	return replacementStep(ctx, func() error {
		return unix.Fchflags(int(target.Fd()), int(s.Flags&^UFCompressed|targetFlags&UFCompressed))
	})
}

func restoreReplacementACL(source, target *os.File) error {
	supported, err := replacementVolumeACL(source)
	if err != nil || !supported {
		return err
	}
	from, err := NewHeldMetadata(source)
	if err != nil {
		return err
	}
	security, err := from.CaptureACL()
	if err != nil {
		return err
	}
	to, err := NewHeldMetadata(target)
	if err != nil {
		return err
	}
	return to.SetACL(security.Security.ACL)
}
