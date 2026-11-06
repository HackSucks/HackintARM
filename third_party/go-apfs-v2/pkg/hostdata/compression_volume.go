package hostdata

import (
	"context"
	"errors"
	"os"
)

// CompressionVolume is one observed Darwin mount context. Filesystem is the
// native filesystem name, including an unrecognized name when actually observed.
// Flags are raw Darwin mount flags; zero is an observation, not a default.
type CompressionVolume struct {
	Filesystem string
	Flags      uint32
}

// QueryCompressionVolume observes filesystem name and flags in one held-file
// Fstatfs call. It neither follows the original pathname nor closes the file.
// Foreign callers retain the observation independently of their receiving host;
// native Linux/Windows mount flags cannot substitute for this Darwin context.
func QueryCompressionVolume(ctx context.Context, file *os.File) (CompressionVolume, error) {
	return queryCompressionVolumeUsing(ctx, file, nativeCompressionVolume)
}

func queryCompressionVolumeUsing(ctx context.Context, file *os.File, query func(int) (CompressionVolume, error)) (CompressionVolume, error) {
	if err := ctx.Err(); err != nil {
		return CompressionVolume{}, err
	}
	var value CompressionVolume
	err := withXattrDescriptor(file, func(fd int) error { var e error; value, e = query(fd); return e })
	if err = errors.Join(err, ctx.Err()); err != nil {
		return CompressionVolume{}, err
	}
	return value, nil
}
