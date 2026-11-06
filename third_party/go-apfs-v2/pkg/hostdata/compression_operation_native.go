package hostdata

import (
	"context"
	"io/fs"
	"os"
)

// OpenNativeCompressionInput opens a native Darwin data file for read/write
// compression acquisition. The returned input is owned by Recompress after a
// successful opener callback; otherwise the caller must close it. Opening can
// itself decompress an existing compressed file. Symlinks follow native open
// behavior; callers requiring rooted containment must supply a rooted opener.
//
// This binding is specifically for native Darwin metadata. Foreign inputs on
// any host use an explicit CompressionInput with captured Darwin metadata and
// mount policy; this function never reinterprets native Windows/Linux flags.
func OpenNativeCompressionInput(ctx context.Context, name string) (CompressionInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return openNativeCompressionInput(ctx, name)
}

// NewNativeCompressionInput transfers ownership of a freshly acquired O_RDWR
// Darwin file to the native compression lifecycle. The caller can acquire it
// through os.Root.OpenFile to preserve a namespace boundary. Successful native
// acquisition may already have decompressed the file before this call.
//
// Binding performs no stat, open, duplication, seek or other native operation.
// Admission and descriptor errors remain at Recompress's existing checkpoints.
// On success Recompress owns and closes the input; on error the caller retains
// the file. Context cancellation never rolls back effects of the preceding open.
// Other hosts use explicit foreign metadata providers instead of this binding.
func NewNativeCompressionInput(ctx context.Context, file *os.File) (CompressionInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if file == nil {
		return nil, fs.ErrInvalid
	}
	return newNativeCompressionInput(ctx, file)
}
