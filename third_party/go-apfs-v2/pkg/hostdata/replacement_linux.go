package hostdata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func prepareReplacementContext(ctx context.Context, _ *os.File, path string, _ os.FileInfo) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
}

func restoreReplacementMetadataContext(ctx context.Context, source, target *os.File, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return restoreReplacementLinux(ctx, source, target, info, replacementLinuxXattrs{
		remove: unix.Fremovexattr, list: unix.Flistxattr, get: unix.Fgetxattr, set: unix.Fsetxattr,
	})
}

// Keep failure injection local to one restoration; native callers always supply
// the descriptor-bound operations above.
type replacementLinuxXattrs struct {
	remove func(int, string) error
	list   func(int, []byte) (int, error)
	get    func(int, string, []byte) (int, error)
	set    func(int, string, []byte, int) error
}

func restoreReplacementLinux(ctx context.Context, source, target *os.File, info os.FileInfo, attrs replacementLinuxXattrs) error {
	s := info.Sys().(*syscall.Stat_t)
	if err := replacementStep(ctx, func() error { return target.Chown(int(s.Uid), int(s.Gid)) }); err != nil {
		return err
	}
	// ListXattrs is intentionally best effort for image extraction. Replacing a
	// file requires a bounded descriptor-based copy which fails on lost metadata.
	fd, to := int(source.Fd()), int(target.Fd())
	// A newly created staging file may have inherited a default directory ACL.
	// Remove it before copying, including when the original file has no ACL.
	if err := replacementStep(ctx, func() error {
		err := attrs.remove(to, PosixACLAccessName)
		// Only the native absence/capability result is harmless. Let the
		// surrounding checkpoint retain any concurrent cancellation.
		if errors.Is(err, unix.ENODATA) || isUnsupported(err) {
			return nil
		}
		return err
	}); err != nil {
		return err
	}
	size, err := replacementValue(ctx, func() (int, error) { return attrs.list(fd, nil) })
	if isUnsupported(err) {
		return replacementStep(ctx, func() error { return target.Chmod(info.Mode()) })
	}
	if err != nil {
		return err
	}
	const limit = 8 << 20
	if size > limit {
		return fmt.Errorf("%w: extended attribute names exceed limit", ErrUnsupportedReplacement)
	}
	names := make([]byte, size)
	size, err = replacementValue(ctx, func() (int, error) { return attrs.list(fd, names) })
	if err != nil {
		return err
	}
	if size > len(names) {
		return fmt.Errorf("extended attribute list changed")
	}
	for _, name := range bytes.Split(names[:size], []byte{0}) {
		if len(name) == 0 {
			continue
		}
		size, err := replacementValue(ctx, func() (int, error) { return attrs.get(fd, string(name), nil) })
		if err != nil {
			return err
		}
		if size > limit {
			return fmt.Errorf("%w: extended attributes exceed limit", ErrUnsupportedReplacement)
		}
		value := make([]byte, size)
		size, err = replacementValue(ctx, func() (int, error) { return attrs.get(fd, string(name), value) })
		if err != nil {
			return err
		}
		if size > len(value) {
			return fmt.Errorf("extended attribute value changed")
		}
		if err := replacementStep(ctx, func() error { return attrs.set(to, string(name), value[:size], 0) }); err != nil {
			return err
		}
	}
	return replacementStep(ctx, func() error { return target.Chmod(info.Mode()) })
}
