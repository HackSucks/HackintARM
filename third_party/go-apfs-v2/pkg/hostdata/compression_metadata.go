package hostdata

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

// QueryCompression inspects the caller-held file's native Darwin compression
// metadata. It reads only com.apple.decmpfs, bounded by attributeBytes, and queries
// resource-fork size only for a fork-based storage type. It never enumerates
// unrelated attributes, reads fork contents or reopens a pathname. The file
// remains caller-owned and pinned against Close through capture and parsing.
//
// Darwin's xattr API requires a complete value buffer, so attributeBytes is an
// explicit allocation budget, not a file-size or resource-fork limit. A changed
// size or flag is an error. Callers must exclude concurrent changes, including
// same-size content edits that these observations cannot detect.
//
// Other hosts return errors.ErrUnsupported for this native Darwin view. Their
// explicit image/carrier state supplies decmpfs.Metadata directly; Linux flags
// and Windows attributes must never be reinterpreted as Darwin BSD flags.
func QueryCompression(ctx context.Context, file *os.File, attributeBytes int) (decmpfs.Info, error) {
	return queryCompressionUsing(ctx, file, attributeBytes, nativeCompressionStat, getCaptureXattrFD)
}

func queryCompressionUsing(ctx context.Context, file *os.File, attributeBytes int, stat func(int) (uint32, uint64, error), get func(int, string, []byte) (int, error)) (decmpfs.Info, error) {
	if ctx == nil || attributeBytes < 0 {
		return decmpfs.Info{}, fs.ErrInvalid
	}
	var info decmpfs.Info
	err := withXattrDescriptor(file, func(fd int) error {
		metadata, err := captureCompressionMetadata(ctx, attributeBytes,
			func() (uint32, uint64, error) { return stat(fd) },
			func(name string, p []byte) (int, error) { return get(fd, name, p) })
		if err != nil {
			return err
		}
		info, err = decmpfs.Query(ctx, metadata)
		return err
	})
	if err != nil {
		return decmpfs.Info{}, err
	}
	return info, nil
}

func captureCompressionMetadata(ctx context.Context, limit int, stat func() (uint32, uint64, error), get func(string, []byte) (int, error)) (decmpfs.Metadata, error) {
	zero := decmpfs.Metadata{}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	flags, size, err := stat()
	if err != nil {
		return zero, err
	}
	result := decmpfs.Metadata{Flags: flags, LogicalSize: size, ResourceForkSize: -1}
	if flags&UFCompressed == 0 {
		return result, ctx.Err()
	}
	value, present, err := readVisibleXattr(func(p []byte) (int, error) { return get(DecmpfsName, p) }, limit)
	if err != nil {
		return zero, err
	}
	if present {
		result.Attribute = bytes.NewReader(value)
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	if len(value) >= 16 && string(value[:4]) == "fpmc" {
		switch binary.LittleEndian.Uint32(value[4:8]) {
		case 4, 8, 10, 12, 14, 16:
			fork, present, err := visibleXattrSize(func(p []byte) (int, error) { return get(ResourceForkName, p) })
			if err != nil {
				return zero, err
			}
			if present {
				result.ResourceForkSize = int64(fork)
			}
		}
	}
	lastFlags, lastSize, err := stat()
	if err != nil {
		return zero, err
	}
	if lastFlags != flags || lastSize != size {
		return zero, ErrXattrChanged
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	return result, nil
}

// CompressionVolumeFlags returns the held file's observed Darwin mount flags.
// The caller retains the volume context with foreign metadata when it needs to
// reproduce storage selection elsewhere. In particular, MNT_CPROTECT (0x80)
// prevents Apple's compressor from selecting inline storage. An unknown native
// host is an explicit error, never a fabricated unprotected Darwin volume.
func CompressionVolumeFlags(ctx context.Context, file *os.File) (uint32, error) {
	return compressionVolumeFlagsUsing(ctx, file, nativeCompressionVolumeFlags)
}

func compressionVolumeFlagsUsing(ctx context.Context, file *os.File, query func(int) (uint32, error)) (uint32, error) {
	if ctx == nil {
		return 0, fs.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var flags uint32
	err := withXattrDescriptor(file, func(fd int) error { var e error; flags, e = query(fd); return e })
	err = errors.Join(err, ctx.Err())
	if err != nil {
		return 0, err
	}
	return flags, nil
}
