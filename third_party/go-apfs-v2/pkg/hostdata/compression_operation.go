package hostdata

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

// CompressionFileState captures size and restoration metadata from one held
// data handle. Size is the logical data length after read/write acquisition.
// Opening a compressed Darwin file for writing can itself decompress it.
type CompressionFileState struct {
	Size int64
	Stat StatCopySource
}

// CompressionInput binds admission to one opened object. Snapshot is called
// once for admission and again for restoration after eligibility is established.
// ProbeWrite must issue the native zero-byte write rather than elide it.
// Duplicate returns an independently owned handle to the same object.
// Every returned handle is owned and closed by Recompress.
type CompressionInput interface {
	Snapshot() (CompressionFileState, error)
	ProbeWrite() error
	Duplicate() (CompressionStream, error)
	Close() error
}

// CompressionStream supplies the held source and installation operations. Its
// volume flags are observed Darwin mount policy, including MNT_CPROTECT; foreign
// providers must receive them explicitly rather than infer them from host OS.
// ReadAt follows io.ReaderAt's short-read contract. Installation cannot resolve
// a mutable pathname. The resource fork is opened before VolumeFlags or reads.
type CompressionStream interface {
	io.ReaderAt
	CompressionInstallationBackend
	VolumeFlags() (uint32, error)
	Close() error
}

// CompressionStage owns private, initially empty, bounded-access staging.
// Close must close its handles and remove temporary storage, including on error.
// The stage must not alias the input, resource fork or any published object.
type CompressionStage interface {
	io.ReaderAt
	io.WriterAt
	Close() error
}

// RecompressionOptions supplies native content policy and private staging. Name
// is the final logical path component: native compression declines names with
// the AppleDouble "._" prefix after opening/statting the data file. NewStage is
// invoked only after eligibility, acquisition and volume-policy observation.
type RecompressionOptions struct {
	Name     string
	Encoding decmpfs.EncodeOptions
	NewStage func(context.Context) (CompressionStage, error)
}

// RecompressionResult separates admission from later compression and cleanup.
// Accepted means read/write acquisition and the first stat succeeded; it does
// not imply activation or absence of errors. Declined is "eligibility",
// "content" or "resource-fork" for a normal policy decline. Installation retains
// exact partial mutations and ignored native restoration errors. Failures holds
// acquisition, staging and owned-handle cleanup errors in execution order.
type RecompressionResult struct {
	Accepted     bool
	Declined     string
	Installation CompressionInstallationResult
	Failures     []StatCopyFailure
}

// Recompress applies the native default open/eligibility/encode/install/close
// sequence to a native or explicit foreign provider. open must perform read/write
// acquisition and returns an owned handle. The caller excludes unrelated edits;
// this protocol does not make a snapshot or promise rollback. Initial open/stat
// failure rejects admission, while subsequent failures retain Accepted=true.
// Callers must inspect Accepted separately when reproducing codesign's handling
// of native queue admission; the returned error always retains operational failure.
//
// Cancellation stops before destructive installation. Once the ordinary fork is
// truncated, InstallCompression completes activation/restoration before returning
// cancellation. All acquired handles and private staging are closed on every path.
// Native ignored installation errors remain in Installation, not the returned
// error. A native framework crash is represented by an operation error, never a
// deliberate crash of the Go process.
func Recompress(ctx context.Context, open func(context.Context) (CompressionInput, error), options RecompressionOptions) (result RecompressionResult, err error) {
	if open == nil || options.NewStage == nil || strings.ContainsAny(options.Name, "/\x00") {
		return result, fs.ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, ctx.Err()) }()
	record := func(operation string, e error) error {
		if e != nil {
			result.Failures = append(result.Failures, StatCopyFailure{operation, e})
		}
		return e
	}
	input, e := open(ctx)
	if e != nil {
		return result, record("open", e)
	}
	if input == nil {
		return result, record("open", fs.ErrInvalid)
	}
	defer func() { err = errors.Join(err, record("close-input", input.Close())) }()
	if err = ctx.Err(); err != nil {
		return result, err
	}
	admission, e := input.Snapshot()
	if e != nil {
		return result, record("admission-stat", e)
	}
	result.Accepted = true
	if admission.Size < 0 {
		return result, record("admission-stat", fs.ErrInvalid)
	}
	if admission.Size <= 16384 || admission.Size > 512<<20 || strings.HasPrefix(options.Name, "._") {
		result.Declined = "eligibility"
		return result, ctx.Err()
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	source, e := input.Snapshot()
	if e != nil {
		return result, record("source-stat", e)
	}
	if source.Stat.Mode > 65535 {
		return result, record("source-stat", fs.ErrInvalid)
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = record("probe-write", input.ProbeWrite()); err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	stream, e := input.Duplicate()
	if e != nil {
		return result, record("duplicate", e)
	}
	if stream == nil {
		return result, record("duplicate", fs.ErrInvalid)
	}
	defer func() { err = errors.Join(err, record("close-stream", stream.Close())) }()
	if err = ctx.Err(); err != nil {
		return result, err
	}
	fork, e := stream.OpenCompressionFork()
	if e != nil {
		return result, record("open-fork", e)
	}
	if fork == nil {
		return result, record("open-fork", fs.ErrInvalid)
	}
	defer func() {
		if fork != nil {
			finishCompressionFork(fork, &result.Installation.Fork)
		}
	}()
	if err = ctx.Err(); err != nil {
		return result, err
	}
	flags, e := stream.VolumeFlags()
	if e != nil {
		return result, record("volume", e)
	}
	encoding := options.Encoding
	encoding.ResourceForkOnly = encoding.ResourceForkOnly || flags&0x80 != 0
	if err = ctx.Err(); err != nil {
		return result, err
	}
	stage, e := options.NewStage(ctx)
	if e != nil {
		return result, record("stage-create", e)
	}
	if stage == nil {
		return result, record("stage-create", fs.ErrInvalid)
	}
	defer func() { err = errors.Join(err, record("stage-close", stage.Close())) }()
	storage, e := decmpfs.Encode(ctx, stream, admission.Size, stage, encoding)
	if e != nil {
		return result, record("encode", e)
	}
	if storage.Attribute == nil {
		result.Declined = "content"
		finishCompressionFork(fork, &result.Installation.Fork)
		fork = nil
		restoreCompressionDecline(source.Stat, stream, &result.Installation.Commit)
		return result, ctx.Err()
	}
	// InstallCompression owns the already-open fork from this point onward.
	backend := acquiredCompressionFork{CompressionInstallationBackend: stream, fork: fork}
	fork = nil
	result.Installation, err = InstallCompression(ctx, storage, stage, source.Stat, &backend)
	if !backend.taken {
		// Validation/cancellation can fail before InstallCompression asks for it.
		finishCompressionFork(backend.fork, &result.Installation.Fork)
	}
	if result.Installation.Fork.Declined {
		result.Declined = "resource-fork"
	}
	return result, err
}

type acquiredCompressionFork struct {
	CompressionInstallationBackend
	fork  CompressionForkWriter
	taken bool
}

func (b *acquiredCompressionFork) OpenCompressionFork() (CompressionForkWriter, error) {
	b.taken = true
	return b.fork, nil
}

func restoreCompressionDecline(source StatCopySource, backend CompressionCommitBackend, result *CompressionCommitResult) {
	if e := backend.SyncData(); e != nil {
		result.Failures = append(result.Failures, StatCopyFailure{"sync", e})
	}
	e := backend.SetCompressionTimes(source.Times.Modify.Truncate(time.Microsecond), source.Times.Access.Truncate(time.Microsecond))
	result.TimesRestored = e == nil
	if e != nil {
		result.Failures = append(result.Failures, StatCopyFailure{"times", e})
	}
	result.Completed = true
}
