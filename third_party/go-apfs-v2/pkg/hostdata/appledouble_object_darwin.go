package hostdata

import (
	"context"
	"errors"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"golang.org/x/sys/unix"
)

type hostObjectAttributes struct{ file *os.File }

func newHostObjectAttributes(file *os.File) (objectAttributes, error) {
	return &hostObjectAttributes{file: file}, nil
}
func (a *hostObjectAttributes) control(call func(int) error) error {
	conn, err := a.file.SyscallConn()
	if err != nil {
		return err
	}
	var native error
	err = conn.Control(func(fd uintptr) { native = call(int(fd)) })
	err = errors.Join(err, native)
	if errors.Is(err, unix.EPERM) {
		err = errors.Join(ErrXattrRestoreNotPermitted, err)
	}
	return strictXattrError(err)
}
func (a *hostObjectAttributes) listSize() (n int, err error) {
	err = a.control(func(fd int) error { n, err = unix.Flistxattr(fd, nil); return err })
	return
}
func (a *hostObjectAttributes) names(capacity int) (names []string, err error) {
	if capacity < 0 || capacity > MaxXattrListSize {
		return nil, errors.Join(ErrUnpackListAllocation, ErrXattrTooLarge)
	}
	buffer := make([]byte, capacity)
	var n int
	err = a.control(func(fd int) error { n, err = unix.Flistxattr(fd, buffer); return err })
	if err != nil {
		return nil, err
	}
	if n < 0 || n > len(buffer) {
		return nil, ErrXattrChanged
	}
	return parseXattrNames(buffer[:n])
}
func (a *hostObjectAttributes) size(name string) (size int64, err error) {
	var n int
	err = a.control(func(fd int) error { n, err = unix.Fgetxattr(fd, name, nil); return err })
	return int64(n), err
}
func (a *hostObjectAttributes) read(name string, dst []byte) (n int, err error) {
	err = a.control(func(fd int) error { n, err = unix.Fgetxattr(fd, name, dst); return err })
	return
}
func (a *hostObjectAttributes) write(name string, value []byte) error {
	return a.control(func(fd int) error { return unix.Fsetxattr(fd, name, value, 0) })
}
func (a *hostObjectAttributes) remove(name string) error {
	return a.control(func(fd int) error { return unix.Fremovexattr(fd, name) })
}
func (a *hostObjectAttributes) truncateFork(mode uint32) error {
	fork, err := openPathResourceForkNative(a.file, true, mode)
	if err != nil {
		return err
	}
	return fork.Close()
}
func (a *hostObjectAttributes) quarantine(ctx context.Context, profile appledouble.QuarantineProfile) (*appledouble.Quarantine, error) {
	return CaptureQuarantineFile(ctx, a.file, profile)
}
func (a *hostObjectAttributes) applyQuarantine(ctx context.Context, q *appledouble.Quarantine, process QuarantineProcessCapture, _ uint32) error {
	return ApplyQuarantineFile(ctx, a.file, q, process)
}
func (a *hostObjectAttributes) noSetID() (value bool, err error) {
	err = a.control(func(fd int) error {
		var stat unix.Statfs_t
		if err := unix.Fstatfs(fd, &stat); err != nil {
			return err
		}
		value = stat.Flags&unix.MNT_NOSUID != 0
		return nil
	})
	return
}
