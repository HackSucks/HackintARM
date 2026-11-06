package hostdata

import (
	"errors"
	"fmt"
	"io/fs"
	"time"
)

// ErrStatFlagsAgain classifies Darwin EAGAIN from a compare-and-swap flag write.
// Providers should join it with the original error. Other errors cause the
// native fchflags fallback immediately; they are not retried as contention.
var ErrStatFlagsAgain = errors.New("stat flags compare-and-swap temporarily unavailable")

// StatCopySource is captured Darwin stat metadata. Mode includes Darwin file
// type bits. Only Modify and Access are submitted; Birth and Change are not
// explicitly copied by this stage. The destination filesystem owns side effects.
type StatCopySource struct {
	UID, GID, Mode, Flags uint32
	Times                 FileTimes
}

// StatCopyOptions controls copyfile's final stat stage. Volume policy follows
// SecurityCopyOptions' precedence and lazy query rules, but this stage queries
// afresh even if a preceding security stage has already queried the volumes.
type StatCopyOptions struct {
	AlwaysCopySetID, ForbidCopySetID          bool
	SourceNoSetID, DestinationNoSetID         bool
	VolumePolicy                              SecurityCopyVolumePolicy
	MakeInvisible, PreserveDestinationTracked bool
}

// StatCopyBackend binds all calls to the same held destination or foreign
// metadata object. No method may reopen a mutable pathname. Caller and provider
// own lifetime, authorization and exclusion of concurrent unrelated mutations.
//
// CompareAndSwapFlags returns the flags observed BEFORE the attempted update.
// With nil error, matching expected means written; a mismatch means no write
// occurred and supplies the next comparison value. On error, actual is ignored.
// SetTimes submits modification then access with nanosecond precision. Every
// operation may have partial effects; no rollback is promised. Implementations
// on every OS can bind native objects or explicit foreign-metadata carriers.
type StatCopyBackend interface {
	SetTimes(modify, access time.Time) error
	Chown(uid, gid uint32) error
	Chmod(mode uint16) error
	ReadFlags() (uint32, error)
	CompareAndSwapFlags(expected, replacement uint32) (actual uint32, err error)
	Chflags(flags uint32) error
}

// StatCopyFailure retains an actual error in execution order. Operation is
// "times", "ownership", "mode", "read-flags", "compare-flags" or "flags".
// A recovered CAS failure remains visible; Failures alone does not say whether
// a later fallback repaired it. Inspect FlagsApplied and recapture when needed.
type StatCopyFailure struct {
	Operation string
	Err       error
}

// StatCopyResult separates sequence completion from successful preservation.
// Copyfile ignores stat write failures; this API retains every error. Writes
// counts attempted writes (including unsuccessful comparisons), not reads.
// FlagComparisons includes mismatches and errors; FlagsFallback records an
// attempted Chflags. FlagsApplied is true only after a confirmed flag write.
type StatCopyResult struct {
	Completed, FlagsApplied, FlagsFallback bool
	Writes, FlagComparisons                int
	Failures                               []StatCopyFailure
	VolumeQueries                          []SecurityCopyVolumeQuery
}

// CopyStat executes the complete copyfile_stat ordering: volume policy, times,
// ownership, permissions, then BSD flags. Flags use four bounded CAS attempts
// before falling back to Chflags. Compressed sources without immutable/append
// bits request times again even if the flag update failed. Destination protected
// flags survive; source tracked/protected flags are omitted, with optional
// destination tracked preservation and Finder-invisible conversion.
//
// Backend or option validation errors stop before any callbacks. Operational
// errors are retained while the native sequence continues, including a failed
// destination flag read. Completed never means all metadata was preserved.
// This pure-Go stage is not source acquisition, the preceding security stage,
// AppleDouble deferred ACL replacement or a complete copyfile lifecycle.
func CopyStat(source StatCopySource, options StatCopyOptions, backend StatCopyBackend) (result StatCopyResult, err error) {
	if backend == nil {
		return result, fmt.Errorf("stat copy backend: %w", fs.ErrInvalid)
	}
	if options.VolumePolicy != nil && (options.SourceNoSetID || options.DestinationNoSetID) {
		return result, fmt.Errorf("mixed captured and queried stat volume policy: %w", fs.ErrInvalid)
	}
	policy := SecurityCopyOptions{Stat: true, AlwaysCopySetID: options.AlwaysCopySetID, ForbidCopySetID: options.ForbidCopySetID, SourceNoSetID: options.SourceNoSetID, DestinationNoSetID: options.DestinationNoSetID, VolumePolicy: options.VolumePolicy}
	var queries SecurityCopyResult
	mode := uint16(source.Mode &^ 0170000)
	if securityCopyNoSetID(policy, &queries) {
		mode &^= 06000
	}
	result.VolumeQueries = queries.VolumeQueries
	result.write("times", backend.SetTimes(source.Times.Modify, source.Times.Access))
	result.write("ownership", backend.Chown(source.UID, source.GID))
	result.write("mode", backend.Chmod(mode))
	// Pinned copyfile_private.h: SF_RESTRICTED | SF_NOUNLINK | UF_DATAVAULT.
	const protected = uint32(0x80000 | 0x100000 | 0x80)
	const tracked, hidden, compressed = uint32(0x40), uint32(0x8000), uint32(0x20)
	flags := source.Flags &^ (protected | tracked)
	if options.MakeInvisible {
		flags |= hidden
	}
	preserve := protected
	if options.PreserveDestinationTracked {
		preserve |= tracked
	}
	result.copyFlags(flags, preserve, backend)
	if flags&compressed != 0 && flags&(0x2|0x4|0x20000|0x40000) == 0 {
		result.write("times", backend.SetTimes(source.Times.Modify, source.Times.Access))
	}
	result.Completed = true
	return result, nil
}

func (r *StatCopyResult) failure(operation string, err error) {
	if err != nil {
		r.Failures = append(r.Failures, StatCopyFailure{Operation: operation, Err: err})
	}
}
func (r *StatCopyResult) write(operation string, err error) { r.Writes++; r.failure(operation, err) }
