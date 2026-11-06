// Package decmpfs writes bounded native filesystem-compression resource forks.
// It supplies the storage codec; callers decide whether to compress a file and
// own installation, metadata policy and cleanup of partial output.
package decmpfs

import (
	"context"
	"io"

	internal "github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
)

// EncodedFork describes completed output. Attribute is the 16-byte
// com.apple.decmpfs value; Size is the resource fork extent. The caller must
// truncate a reused destination to Size after successful encoding.
type EncodedFork = internal.EncodedFork

// EncodeFork encodes size logical bytes from source into destination. It reads
// at most 64 KiB per call, writes one block or table entry at a time and does not
// retain the complete input, output or index. Codecs use bounded working state.
//
// kind accepts native types 3/4 (zlib), 7/8 (LZVN), 9/10 (stored), 11/12 (LZFSE)
// and 13/14 (LZBITMAP). Output always uses the corresponding resource-fork type.
// Native 32-bit physical offsets still constrain representable output; logical
// size is 64-bit. Empty files are rejected by this storage primitive.
//
// The function never closes handles, installs attributes, changes file flags or
// rolls back writes. On error the result is zero and partial output must be
// discarded. Cancellation is observed between I/O and codec calls. An I/O call
// already in progress must return before cancellation can take effect.
func EncodeFork(ctx context.Context, source io.ReaderAt, size int64, kind uint32, destination io.WriterAt) (EncodedFork, error) {
	return internal.EncodeFork(ctx, source, size, kind, destination)
}
