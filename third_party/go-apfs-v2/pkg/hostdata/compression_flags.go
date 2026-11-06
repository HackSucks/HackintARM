package hostdata

import (
	"context"
	"errors"
	"io/fs"
)

// CompressionFlagsBackend binds compression activation to one held inode or
// explicit foreign metadata object. Existing HeldMetadata and LogicalMetadata
// implement this contract. CompareAndSwapFlags follows StatCopyBackend's
// before-value semantics; ErrStatFlagsAgain identifies temporary contention.
type CompressionFlagsBackend interface {
	ReadFlags() (uint32, error)
	CompareAndSwapFlags(expected, replacement uint32) (actual uint32, err error)
}

// CompressionFlagResult records actual compare attempts and their outcome.
// Applied means a confirmed update. Other flags survive each freshly read
// comparison; failure never falls back to an unconditional flag overwrite.
type CompressionFlagResult struct {
	Applied            bool
	Reads, Comparisons int
	Actual             uint32
	// LastComparisonError distinguishes exhausted value mismatches from a
	// failed final native call; the compressor restores times after the former.
	LastComparisonError error
	Failures            []StatCopyFailure
}

// ActivateCompression follows Apple's compressor's four-attempt BSD flag
// activation sequence. The attribute and resource-fork storage must already
// be installed and the ordinary data fork truncated by the caller. This stage
// does not validate payload bytes, restore data or take ownership of handles.
// In contrast to copyfile's stat stage, non-contention errors stop immediately
// and exhausted comparisons never fall back to Chflags.
//
// Cancellation stops before the next native operation and may leave completed
// prior mutations. Callers own the final cancellable boundary of their overall
// installation; a non-cancellable activation context can finish an already
// committed data-fork transition while retaining cancellation separately.
func ActivateCompression(ctx context.Context, backend CompressionFlagsBackend) (result CompressionFlagResult, err error) {
	if ctx == nil || backend == nil {
		return result, fs.ErrInvalid
	}
	for range 4 {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		result.Reads++
		flags, e := backend.ReadFlags()
		if e != nil {
			result.Failures = append(result.Failures, StatCopyFailure{"read-flags", e})
			return result, e
		}
		if err = ctx.Err(); err != nil {
			return result, err
		}
		result.Comparisons++
		actual, e := backend.CompareAndSwapFlags(flags, flags|UFCompressed)
		result.LastComparisonError = e
		if e != nil {
			result.Failures = append(result.Failures, StatCopyFailure{"compare-flags", e})
			if !errors.Is(e, ErrStatFlagsAgain) {
				return result, e
			}
			err = e
			continue
		}
		result.Actual = actual
		if actual == flags {
			result.Applied = true
			return result, nil
		}
		err = ErrStatFlagsAgain
	}
	return result, err
}
