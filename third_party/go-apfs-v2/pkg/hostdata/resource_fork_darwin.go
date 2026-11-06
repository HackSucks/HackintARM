package hostdata

import (
	"context"
	"errors"
	"io/fs"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"golang.org/x/sys/unix"
)

func openNativeResourceFork(fd int, writable bool) (*os.File, error) {
	return openNativeResourceForkContext(context.TODO(), fd, writable)
}
func openNativeResourceForkContext(ctx context.Context, fd int, writable bool) (*os.File, error) {
	return openNativeResourceForkContextUsing(ctx, fd, writable, func(ctx context.Context, fd int, path string, flags int, mode uint32) (int, error) {
		return openResourceForkAtContextUsing(ctx, fd, path, flags, mode, osversion.Detect, unix.Openat, func(fd, flags int, mode uint32) (int, error) {
			return openLegacyResourceForkContext(ctx, fd, flags, mode)
		})
	})
}
func openNativeResourceForkContextUsing(ctx context.Context, fd int, writable bool, open func(context.Context, int, string, int, uint32) (int, error)) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC
	if writable {
		flags = unix.O_RDWR | unix.O_CREAT | unix.O_CLOEXEC
	}
	fork, err := open(ctx, fd, "..namedfork/rsrc", flags, 0600)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, errors.Join(err, unix.Close(fork))
	}
	return os.NewFile(uintptr(fork), "resource fork"), nil
}
func openResourceForkAt(fd int, path string, flags int, mode uint32) (int, error) {
	// This legacy API has no caller context. Do not pass a nil Context.
	return openResourceForkAtUsing(fd, path, flags, mode, osversion.Detect, unix.Openat, openLegacyResourceFork)
}
func openResourceForkAtUsing(fd int, path string, flags int, mode uint32,
	detect func(context.Context) (osversion.Version, error),
	openat func(int, string, int, uint32) (int, error), legacy func(int, int, uint32) (int, error)) (int, error) {
	return openResourceForkAtContextUsing(context.TODO(), fd, path, flags, mode, detect, openat, legacy)
}
func openResourceForkAtContextUsing(ctx context.Context, fd int, path string, flags int, mode uint32,
	detect func(context.Context) (osversion.Version, error), openat func(int, string, int, uint32) (int, error), legacy func(int, int, uint32) (int, error)) (int, error) {
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	if path != "..namedfork/rsrc" {
		return -1, fs.ErrInvalid
	}
	version, err := detect(ctx)
	if err != nil {
		return -1, err
	}
	profile, err := osversion.ProfileForMacOS(version)
	if err != nil {
		return -1, err
	}
	if err = ctx.Err(); err != nil {
		return -1, err
	}
	if profile == osversion.MacOS15 {
		return legacy(fd, flags, mode)
	}
	return openat(fd, path, flags, mode)
}
