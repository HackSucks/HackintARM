package hostdata

import (
	"context"
	"errors"
	"io/fs"
	"time"

	internal "github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

// ErrCompressionAttributeAccess identifies precisely Darwin EACCES while
// installing com.apple.decmpfs. Backends join it with the original error.
// EPERM and other permission failures do not request a temporary mode change.
var ErrCompressionAttributeAccess = errors.New("compression attribute access denied")

// CompressionCommitBackend binds the final compression transition to one held
// inode or explicit foreign object. Resource-fork storage must already have
// been installed and its writer closed. The caller owns the backend and its
// data handle; no operation may resolve a mutable pathname.
//
// SetCompressionTimes submits modification/access times with native futimes
// microsecond precision. Chmod takes Darwin mode bits. TruncateData(0) removes
// the ordinary data fork; foreign backends must preserve logical bytes in the
// compressed storage, not in a second contradictory ordinary data fork.
type CompressionCommitBackend interface {
	CompressionFlagsBackend
	SetCompressionAttribute([]byte) error
	Chmod(uint16) error
	TruncateData(int64) error
	SyncData() error
	SetCompressionTimes(modify, access time.Time) error
}

// CompressionCommitResult distinguishes actual mutations from sequence
// completion. Failures includes recovered attribute/flag errors and ignored
// synchronization, time or final mode-restoration errors, in execution order.
// Completed does not mean every metadata write succeeded. Nothing rolls back
// completed writes, including a temporary mode after a native terminal error.
type CompressionCommitResult struct {
	AttributeInstalled, TemporaryMode, DataTruncated  bool
	Activated, TimesRestored, ModeRestored, Completed bool
	Flags                                             CompressionFlagResult
	Failures                                          []StatCopyFailure
}

// CommitCompression performs the native compressor's final transition: install
// the attribute, truncate the ordinary data fork, atomically activate the flag,
// synchronize, restore times and restore a temporary mode. Only EACCES on the
// first attribute write requests mode 0600 and one retry. Other errors stop.
// Validated storage must be freshly encoded from the stable logical input;
// this operation checks layout, not payload integrity or source identity.
//
// Cancellation is observed before each operation until truncation. Once
// truncation succeeds, activation and restoration finish without cancellation
// so cancellation alone cannot strand an empty, unactivated data fork. A late
// cancellation is returned after completion; inspect the result before retrying.
// Native operational failures can still leave partial state. The caller owns
// handles and cleanup, and must exclude concurrent content/storage mutation.
func CommitCompression(ctx context.Context, storage decmpfs.EncodedFile, source StatCopySource, backend CompressionCommitBackend) (result CompressionCommitResult, err error) {
	if backend == nil || storage.ForkSize < 0 || source.Mode > 65535 {
		return result, fs.ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = internal.ValidateLayout(storage.Attribute, uint64(len(storage.Attribute)), 0, uint64(storage.ForkSize)); err != nil {
		return result, err
	}
	record := func(operation string, e error) error {
		if e != nil {
			result.Failures = append(result.Failures, StatCopyFailure{operation, e})
		}
		return e
	}
	err = record("attribute", backend.SetCompressionAttribute(storage.Attribute))
	if err != nil {
		if !errors.Is(err, ErrCompressionAttributeAccess) {
			return result, err
		}
		if err = ctx.Err(); err != nil {
			return result, err
		}
		if err = record("temporary-mode", backend.Chmod(0600)); err != nil {
			return result, err
		}
		result.TemporaryMode = true
		if err = ctx.Err(); err != nil {
			return result, err
		}
		if err = record("attribute", backend.SetCompressionAttribute(storage.Attribute)); err != nil {
			return result, err
		}
	}
	result.AttributeInstalled = true
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = record("truncate", backend.TruncateData(0)); err != nil {
		return result, err
	}
	result.DataTruncated = true
	result.Flags, err = ActivateCompression(context.WithoutCancel(ctx), backend)
	result.Failures = append(result.Failures, result.Flags.Failures...)
	if err != nil && !(errors.Is(err, ErrStatFlagsAgain) && result.Flags.Comparisons == 4 && result.Flags.LastComparisonError == nil) {
		return result, errors.Join(err, ctx.Err())
	}
	// Native restores times after four successful comparisons that all lost
	// a race, even though none activated compression. Keep that outcome explicit.
	result.Activated = result.Flags.Applied
	_ = record("sync", backend.SyncData())
	result.TimesRestored = record("times", backend.SetCompressionTimes(source.Times.Modify.Truncate(time.Microsecond), source.Times.Access.Truncate(time.Microsecond))) == nil
	if result.TemporaryMode {
		result.ModeRestored = record("restore-mode", backend.Chmod(uint16(source.Mode))) == nil
	}
	result.Completed = true
	return result, errors.Join(err, ctx.Err())
}
