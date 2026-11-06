package decmpfs

import (
	"context"
	"io"

	internal "github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
)

// EncodeOptions selects the native default content policy's codec and whether
// to allow inline storage. Type zero uses LZVN; ResourceForkOnly defaults false.
type EncodeOptions = internal.EncodeOptions

// EncodedFile holds completed compression storage. Nil Attribute means the
// content policy declined compression. Otherwise it contains the complete
// com.apple.decmpfs value; ForkSize is zero for inline storage, or the exact
// extent of the resource fork written to the caller's destination.
type EncodedFile = internal.EncodedFile

// Encode applies Apple's native default content policy to logical input bytes.
// It shares EncodeFork's bounded I/O and codec implementation, supports every
// codec on every host, and can return inline storage without destination writes.
//
// The caller owns source stability, file eligibility (including permissions,
// entry type and existing metadata), staging, installation and cleanup. This
// operation neither changes a live file nor closes handles. A declined result
// or error can leave partial staged output, which must be discarded. Completed
// fork output must be truncated to ForkSize before installation. Inline output
// does not use the destination; any previous destination content is unchanged.
func Encode(ctx context.Context, source io.ReaderAt, size int64, destination io.WriterAt, options EncodeOptions) (EncodedFile, error) {
	return internal.Encode(ctx, source, size, destination, options)
}
