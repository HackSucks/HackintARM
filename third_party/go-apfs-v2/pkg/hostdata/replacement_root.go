package hostdata

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// RootReplacement is a writable replacement staged beneath an opened root.
// Path is relative to the root supplied to PrepareReplacementAt, suitable for
// PublishContext after writing, RestoreMetadata, syncing and closing File.
// Preparation and cleanup never rename or modify the source.
//
// The caller owns source and root: keep source open and unchanged through
// RestoreMetadata, and root open through Close. Close must be called on success
// and failure, including after a successful rename. Methods are not concurrent.
type RootReplacement struct {
	File *os.File
	Path string

	source        *os.File
	cleanup       *os.File
	info          os.FileInfo
	root, staging *os.Root
	dir           string
	closed        bool
	filesystem    *replacementFilesystem
}

// PrepareReplacementAt prepares a regular source file in a private directory
// beneath parent, relative to root. Destination operations use opened roots and
// handles rather than reconstructing absolute paths. The initial content of
// File is unspecified; write the complete replacement and truncate it.
//
// The supported metadata and Darwin cloning/copying behavior match PrepareReplacement.
// Windows preserves compressed/encrypted inputs and rejects reparse files.
// Ordinary and sparse alternate streams have no aggregate byte or record limit;
// attributes, owner/group and DACL are retained. Encrypted copies require matching
// recipient and recovery keys. Namespace hints are validated against held copy
// handles, and the private Windows directory has its DACL installed at creation. Sparse source replacements retain the sparse attribute; the
// caller supplies all new main data and controls its physical allocation.
// Concurrent modification of the source or staging tree is unsupported. The
// caller must exclude concurrent namespace changes through PublishContext.
func PrepareReplacementAt(source *os.File, root *os.Root, parent string) (*RootReplacement, error) {
	return PrepareReplacementAtContext(context.Background(), source, root, parent)
}

// PrepareReplacementAtContext is the cancellable rooted preparation operation.
// Root containment and caller ownership match PrepareReplacementAt. Cleanup is
// never canceled; individual native calls need not be interruptible.
func PrepareReplacementAtContext(ctx context.Context, source *os.File, root *os.Root, parent string) (*RootReplacement, error) {
	return PrepareReplacementAtWithOptionsContext(ctx, source, root, parent, ReplacementOptions{})
}

// PrepareReplacementAtWithOptionsContext selects portable metadata compatibility;
// containment, cancellation and cleanup match PrepareReplacementAtContext.
func PrepareReplacementAtWithOptionsContext(ctx context.Context, source *os.File, root *os.Root, parent string, options ReplacementOptions) (*RootReplacement, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	profile, err := options.filesystemProfile()
	if err != nil {
		return nil, err
	}
	info, err := replacementValue(ctx, source.Stat)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("prepare replacement: %w: non-regular source", ErrUnsupportedReplacement)
	}
	dir := filepath.Join(parent, ".apfs-replacement-"+rand.Text())
	release, err := makeReplacementDirectoryAt(ctx, root, dir)
	if err != nil {
		if release != nil {
			err = errors.Join(err, release(), root.Remove(dir))
		}
		return nil, err
	}
	stage, err := root.OpenRoot(dir)
	err = errors.Join(err, ctx.Err())
	if err != nil {
		if stage != nil {
			err = errors.Join(err, stage.Close())
		}
		return nil, errors.Join(err, release(), root.Remove(dir))
	}
	r := &RootReplacement{source: source, info: info, root: root, staging: stage, dir: dir, Path: filepath.Join(dir, "replacement")}
	r.File, err = prepareReplacementAtContext(ctx, source, stage, info)
	if err == nil {
		r.cleanup, err = replacementCleanupCapability(r.File)
	}
	if err == nil {
		r.filesystem, err = prepareReplacementFilesystemForProfile(ctx, source, r.File, profile)
	}
	err = errors.Join(err, ctx.Err(), release())
	if err != nil {
		return nil, errors.Join(fmt.Errorf("prepare replacement: %w", err), r.Close())
	}
	return r, nil
}

// RestoreMetadata restores supported metadata after content writes, without
// syncing or closing either file. A failure requires discarding the replacement.
func (r *RootReplacement) RestoreMetadata() error {
	return r.RestoreMetadataContext(context.Background())
}

// RestoreMetadataContext restores rooted replacement metadata with cancellation
// checkpoints. Close remains required on every outcome and is never canceled.
func (r *RootReplacement) RestoreMetadataContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.closed {
		return os.ErrClosed
	}
	current, err := replacementValue(ctx, r.source.Stat)
	if err != nil {
		return err
	}
	if !os.SameFile(r.info, current) {
		return fmt.Errorf("replacement source changed")
	}
	return restoreReplacementMetadataAtContext(ctx, r.source, r.File, r.info)
}

// Close closes the staged file and removes its private directory. It is
// idempotent and safe after File has been closed or renamed. It does not close
// source or the caller's root and does not chmod a committed replacement.
func (r *RootReplacement) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	// Inspect only the private name before using a retained metadata capability.
	// A committed replacement has no name in staging and must not be changed.
	chmodErr := replacementCleanupMetadata(r.staging, r.cleanup)
	var closeErr error
	if r.File != nil {
		closeErr = r.File.Close()
		if errors.Is(closeErr, os.ErrClosed) {
			closeErr = nil
		}
	}
	if r.cleanup != nil {
		closeErr = errors.Join(closeErr, r.cleanup.Close())
	}
	if os.IsNotExist(chmodErr) {
		chmodErr = nil
	}
	removeErr := r.staging.Remove("replacement")
	if os.IsNotExist(removeErr) {
		removeErr = nil
	}
	var carrierErr error
	if r.filesystem != nil {
		carrierErr = r.staging.Remove("._replacement")
		if os.IsNotExist(carrierErr) {
			carrierErr = nil
		}
	}
	return errors.Join(closeErr, chmodErr, removeErr, carrierErr, r.staging.Close(), r.root.Remove(r.dir))
}
