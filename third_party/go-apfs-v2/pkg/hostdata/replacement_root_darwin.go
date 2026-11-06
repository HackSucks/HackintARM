package hostdata

import (
	"context"
	"fmt"
	"os"

	hostflags "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/bsdflags"
	"golang.org/x/sys/unix"
)

func prepareReplacementAtContext(ctx context.Context, source *os.File, stage *os.Root, info os.FileInfo) (file *os.File, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	flags, _ := hostflags.Flags(info)
	if flags&(unix.UF_IMMUTABLE|unix.UF_APPEND|unix.SF_IMMUTABLE|unix.SF_APPEND) != 0 {
		return nil, fmt.Errorf("%w: protected source", ErrUnsupportedReplacement)
	}
	return replacementWithHandle(ctx, func() (*os.File, error) { return stage.Open(".") }, func(dir *os.File) (*os.File, error) {
		// Query and clear security on the held staging directory.
		if err := clearReplacementHeldACL(dir); err != nil {
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
				return unix.Fclonefileat(int(source.Fd()), int(dir.Fd()), "replacement", 0)
			},
			replacementCloneUnavailable,
			func(cloned bool) (*os.File, error) {
				return replacementOpenAfterClone(cloned, func() error { return stage.Chmod("replacement", 0600) }, func(cloned bool) (*os.File, error) {
					flags := os.O_RDWR
					if !cloned {
						flags |= os.O_CREATE | os.O_EXCL
					}
					return stage.OpenFile("replacement", flags, 0600)
				})
			},
			func(target *os.File) error { return copyReplacementMetadataContext(ctx, source, target, info) },
		)
	})
}

func restoreReplacementMetadataAtContext(ctx context.Context, source, target *os.File, info os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return restoreReplacementMetadataContext(ctx, source, target, info)
}
