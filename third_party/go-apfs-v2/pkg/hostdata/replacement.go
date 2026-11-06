package hostdata

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// Replacement is a private, writable file prepared from an existing regular
// file. Write and truncate File, then call RestoreMetadata before closing and
// calling PublishContext. Call Close to discard the staging directory on every path.
// The source must remain open and unchanged until RestoreMetadata returns.
//
// Preparation never changes the source or commits a rename. It deliberately fails
// if it cannot preserve the supported metadata; unlike ListXattrs/SetXattrs,
// missing metadata is not treated as a recoverable fidelity loss.
type Replacement struct {
	File       *os.File
	filesystem *replacementFilesystem
	replacementPlatformState
}

// PrepareReplacement creates a private staging directory under parent on the
// source filesystem. Its initial data is unspecified: callers
// must write the complete replacement and truncate to its intended length.
//
// On Darwin this uses cloning when available and otherwise copies metadata. It
// preserves extended attributes and creation time at native filesystem setter
// precision, and restores the source ACL
// after content writes when the held volume supports ACLs. Protected files are unsupported. Compressed sources
// use a fresh uncompressed stage: the old compression attribute and its owned
// storage fork are excluded; an independent fork on inline-compressed sources
// is preserved. RestoreMetadata keeps the target's own compression state.
// Recompression policy belongs to the caller. On Linux
// ownership, mode and readable extended attributes (including POSIX ACLs) are
// restored. On Windows unencrypted sources use held BackupRead/BackupWrite
// transfers to preserve ordinary and sparse alternate streams, EAs and NTFS
// compression. EFS uses contained, identity-checked CopyFileEx plus explicit EA
// transfer; recipient and recovery keys must match. The owner, group and DACL
// are restored explicitly. Prepare before unlinking the source: a held main-data
// handle alone cannot acquire its alternate streams once Windows marks it for
// deletion. Preparation fails if complete metadata cannot be read.
// Linux bounds the xattr name list and each individual
// value to 8 MiB; values transfer separately without a cumulative byte limit. Darwin's copying fallback bounds names to 1 MiB and
// ordinary values to 8 MiB in aggregate; resource forks stream in 64 KiB chunks
// without that value limit. Modification/access timestamps and Linux inode flags
// are not preserved. No cgo is required.
func PrepareReplacement(source *os.File, parent string) (*Replacement, error) {
	return PrepareReplacementContext(context.Background(), source, parent)
}

// PrepareReplacementContext prepares a private replacement with cancellation
// checkpoints around native calls and between streamed metadata transfers.
// Cleanup always completes independently of cancellation. A single native call
// need not be interruptible. The caller retains ownership of source.
func PrepareReplacementContext(ctx context.Context, source *os.File, parent string) (*Replacement, error) {
	return PrepareReplacementWithOptionsContext(ctx, source, parent, ReplacementOptions{})
}

// PrepareReplacementWithOptionsContext selects portable metadata compatibility;
// cancellation, native metadata, source ownership and cleanup match PrepareReplacementContext.
func PrepareReplacementWithOptionsContext(ctx context.Context, source *os.File, parent string, options ReplacementOptions) (*Replacement, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := options.filesystemProfile(); err != nil {
		return nil, err
	}
	info, err := replacementValue(ctx, source.Stat)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("prepare replacement: %w: non-regular source", ErrUnsupportedReplacement)
	}
	r, err := prepareReplacementPrivateContext(ctx, source, parent, info, options)
	if err != nil {
		return nil, err
	}
	if err = preparePrivateFilesystemReplacement(ctx, r, source, options); err != nil {
		return nil, errors.Join(err, r.Close())
	}
	return r, nil
}

// RestoreMetadata restores metadata after all replacement content has been
// written. On failure the caller must discard the replacement without renaming
// it over the source. It does not sync or close either file.
func (r *Replacement) RestoreMetadata() error {
	return r.RestoreMetadataContext(context.Background())
}

// RestoreMetadataContext restores metadata with cancellation checkpoints.
// Any error requires discarding the uncommitted replacement.
func (r *Replacement) RestoreMetadataContext(ctx context.Context) error {
	return restorePrivateReplacementContext(ctx, r)
}

// Close closes File if necessary and removes the private staging directory.
// It is safe after the caller closes or renames File. It never closes source.
func (r *Replacement) Close() error { return closePrivateReplacement(r) }

// ErrUnsupportedReplacement identifies file types, metadata or filesystems
// whose replacement metadata this package cannot safely preserve.
var ErrUnsupportedReplacement = errors.New("unsupported replacement metadata")
