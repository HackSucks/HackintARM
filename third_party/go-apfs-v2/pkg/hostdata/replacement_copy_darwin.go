package hostdata

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"golang.org/x/sys/unix"
)

func replacementCloneUnavailable(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EXDEV) || errors.Is(err, unix.ENOSYS)
}

func copyReplacementMetadata(source, target *os.File, info os.FileInfo) error {
	return copyReplacementMetadataContext(context.Background(), source, target, info)
}
func copyReplacementMetadataContext(ctx context.Context, source, target *os.File, info os.FileInfo) error {
	birth := info.Sys().(*syscall.Stat_t).Birthtimespec
	stored, err := FilesystemUsesXattrFiles(ctx, source)
	if err != nil {
		return err
	}
	if stored {
		if err = copyReplacementFilesystemMetadataContext(ctx, source, target); err != nil {
			return err
		}
		return SetCreationTime(target, time.Unix(birth.Sec, birth.Nsec))
	}
	return copyReplacementMetadataUsingContext(ctx, replacementCopyOps{
		compressed: info.Sys().(*syscall.Stat_t).Flags&UFCompressed != 0,
		list:       func() ([]string, error) { return ListXattrNames(source, MaxXattrListSize) },
		read: func(name string, limit int) ([]byte, bool, error) {
			if name != DecmpfsName {
				return ReadXattr(source, name, limit)
			}
			var value []byte
			var present bool
			err := withXattrFile(source, name, func(fd int) error {
				var err error
				value, present, err = readVisibleXattr(func(buf []byte) (int, error) { return getCaptureXattrFD(fd, name, buf) }, limit)
				return err
			})
			return value, present, err
		},
		write:    func(name string, value []byte) error { return SetXattr(target, name, value) },
		openFork: func() (replacementFork, error) { return OpenResourceForkContext(ctx, source, false) },
		replaceFork: func(value appledouble.Value) error {
			_, err := ReplaceResourceFork(ctx, target, value)
			return err
		},
		birth: func() error { return SetCreationTime(target, time.Unix(birth.Sec, birth.Nsec)) },
	})
}
