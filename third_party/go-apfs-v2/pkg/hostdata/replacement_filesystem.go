package hostdata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// Metadata is prepared privately before any destination mutation. Carrier
// identity is retained separately: a neighboring file is never trusted merely
// because its name matches. Callers exclude concurrent namespace/metadata edits.
type replacementFilesystem struct {
	source, staged               os.FileInfo
	sourceCarrier, stagedCarrier os.FileInfo
	published                    bool
}

func prepareReplacementFilesystemForProfile(ctx context.Context, source, target *os.File, profile osversion.MacOSProfile) (state *replacementFilesystem, result error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	selected, err := filesystemUsesAppleDouble(source)
	if err != nil || !selected {
		return nil, err
	}
	return prepareReplacementFilesystemUsingForProfile(ctx, source, target, FilesystemMetadataForFile, profile)
}

type replacementFilesystemWriter interface {
	io.WriteCloser
	Sync() error
	Stat() (os.FileInfo, error)
}

func prepareReplacementFilesystemUsing(ctx context.Context, source, target *os.File, open func(context.Context, *os.File) (*FilesystemMetadata, error)) (*replacementFilesystem, error) {
	return prepareReplacementFilesystemUsingForProfile(ctx, source, target, open, osversion.MacOS27)
}

func prepareReplacementFilesystemUsingForProfile(ctx context.Context, source, target *os.File, open func(context.Context, *os.File) (*FilesystemMetadata, error), profile osversion.MacOSProfile) (*replacementFilesystem, error) {
	return prepareReplacementFilesystemWithProfile(ctx, source, target, open, profile, func(staging *FilesystemMetadata) (replacementFilesystemWriter, error) {
		return staging.parent.OpenFile("._"+staging.name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	})
}

func prepareReplacementFilesystemWith(ctx context.Context, source, target *os.File, open func(context.Context, *os.File) (*FilesystemMetadata, error), create func(*FilesystemMetadata) (replacementFilesystemWriter, error)) (state *replacementFilesystem, result error) {
	return prepareReplacementFilesystemWithProfile(ctx, source, target, open, osversion.MacOS27, create)
}

func prepareReplacementFilesystemWithProfile(ctx context.Context, source, target *os.File, open func(context.Context, *os.File) (*FilesystemMetadata, error), profile osversion.MacOSProfile, create func(*FilesystemMetadata) (replacementFilesystemWriter, error)) (state *replacementFilesystem, result error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	original, err := open(ctx, source)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, original.Close()) }()
	staging, err := open(ctx, target)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, staging.Close()) }()
	if !staging.UsesAppleDouble() {
		return nil, ErrUnsupportedReplacement
	}
	state = &replacementFilesystem{source: original.identity, staged: staging.identity}
	carrier, entries, err := original.appleDouble(ctx)
	if err != nil {
		return nil, err
	}
	if carrier != nil {
		defer func() { result = errors.Join(result, carrier.Close()) }()
		state.sourceCarrier, err = carrier.Stat()
		if err != nil {
			return nil, err
		}
	}
	if len(entries) == 0 {
		return state, ctx.Err()
	}
	metadata := appledouble.StreamFile{}
	for _, entry := range entries {
		switch entry.Name {
		case appledouble.FinderInfoName:
			n, e := entry.Value.ReadAt(metadata.FinderInfo[:], 0)
			if n != len(metadata.FinderInfo) || (e != nil && !errors.Is(e, io.EOF)) {
				return nil, errors.Join(io.ErrUnexpectedEOF, e)
			}
		case ResourceForkName:
			// macOS 26/27 reject a nonempty short resource fork; macOS 15
			// accepts it. The independent 220-case native matrix qualifies
			// both outcomes on every receiver. The newer writer rejects a nonempty
			// fork shorter than its 286-byte resource header. The raw codec
			// still represents such input; replacement preserves native failure.
			if profile != osversion.MacOS15 && entry.Value.Size() > 0 && entry.Value.Size() < 286 {
				return nil, syscall.EINVAL
			}
			metadata.ResourceFork = entry.Value
		default:
			metadata.Attrs = append(metadata.Attrs, entry)
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	writer, err := create(staging)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, writer.Close()) }()
	if _, err = metadata.EncodeFilesystemTo(ctx, writer, appledouble.DefaultStreamLimits()); err != nil {
		return state, err
	}
	if err = writer.Sync(); err != nil {
		return state, err
	}
	state.stagedCarrier, err = writer.Stat()
	if err != nil {
		return state, err
	}
	return state, ctx.Err()
}

// ReplacementPublicationError reports a metadata publication failure after the
// data entry has already been replaced. Rename of two foreign filesystem entries
// is not atomic; callers must not infer rollback from this error. Close still
// discards private staging. Native filesystem rename keeps its native semantics.
type ReplacementPublicationError struct{ Err error }

func (e *ReplacementPublicationError) Error() string {
	return "replacement data published; metadata publication failed: " + e.Err.Error()
}
func (e *ReplacementPublicationError) Unwrap() error { return e.Err }

// PublishContext publishes the closed, populated replacement over the original
// source entry. Call RestoreMetadata and sync/close File first. On foreign FAT
// volumes it also publishes the privately prepared AppleDouble metadata. The
// source and parent namespace must remain unchanged since preparation.
//
// Cancellation is checked before publication; once data rename succeeds, its
// paired metadata operation is attempted even if cancellation arrives. A
// ReplacementPublicationError means data was published but metadata failed.
// Close is required on every outcome. This method does not promise durability.
func (r *RootReplacement) PublishContext(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.closed {
		return os.ErrClosed
	}
	if r.filesystem == nil {
		return r.root.Rename(r.Path, name)
	}
	return publishFilesystemReplacement(ctx, r.root, r.Path, name, r.filesystem)
}

// PublishContext is the path-based counterpart of RootReplacement.PublishContext.
// The destination must be in the same parent as the private staging directory.
// Existing callers using os.Rename should use this operation when publishing
// filesystem-selected metadata on Linux or Windows FAT volumes.
func (r *Replacement) PublishContext(ctx context.Context, path string) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.filesystem == nil {
		return os.Rename(r.File.Name(), path)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	stage, err := filepath.Abs(r.File.Name())
	if err != nil {
		return err
	}
	parent := filepath.Dir(absolute)
	relative, err := filepath.Rel(parent, stage)
	if err != nil || !filepath.IsLocal(relative) || filepath.Dir(filepath.Dir(stage)) != parent {
		return os.ErrInvalid
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	return publishFilesystemReplacement(ctx, root, relative, filepath.Base(absolute), r.filesystem)
}

func publishFilesystemReplacement(ctx context.Context, root *os.Root, from, to string, state *replacementFilesystem) error {
	return publishFilesystemReplacementUsing(ctx, from, to, state, replacementPublicationOps{
		stat:   func(name string) (os.FileInfo, error) { return StatMetadata(root, name) },
		rename: root.Rename, remove: root.Remove,
	})
}

type replacementPublicationOps struct {
	stat   func(string) (os.FileInfo, error)
	rename func(string, string) error
	remove func(string) error
}

func publishFilesystemReplacementUsing(ctx context.Context, from, to string, state *replacementFilesystem, ops replacementPublicationOps) error {

	if err := ctx.Err(); err != nil {
		return err
	}
	if state.published || !filepath.IsLocal(from) || !filepath.IsLocal(to) {
		return os.ErrInvalid
	}
	carrier := func(name string) string { return filepath.Join(filepath.Dir(name), "._"+filepath.Base(name)) }
	check := func(name string, want os.FileInfo) error {
		got, err := ops.stat(name)
		if want == nil && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if want == nil || !got.Mode().IsRegular() || !os.SameFile(want, got) {
			return ErrMetadataIdentity
		}
		return nil
	}
	for _, entry := range []struct {
		name string
		info os.FileInfo
	}{{from, state.staged}, {to, state.source}, {carrier(from), state.stagedCarrier}, {carrier(to), state.sourceCarrier}} {
		if err := check(entry.name, entry.info); err != nil {
			return fmt.Errorf("replacement publication %s: %w", entry.name, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ops.rename(from, to); err != nil {
		return err
	}
	state.published = true
	var err error
	if state.stagedCarrier != nil {
		err = ops.rename(carrier(from), carrier(to))
	} else if state.sourceCarrier != nil {
		err = ops.remove(carrier(to))
	}
	if err != nil {
		return errors.Join(&ReplacementPublicationError{err}, ctx.Err())
	}
	return ctx.Err()
}
