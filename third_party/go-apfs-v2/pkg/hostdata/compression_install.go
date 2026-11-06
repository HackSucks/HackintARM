package hostdata

import (
	"context"
	"errors"
	"io"
	"io/fs"

	internal "github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

// CompressionInstallationBackend binds storage installation to one native inode
// or explicit foreign object. Opening the fork must not truncate it. Its returned
// writer is owned by this operation. CompressionForkSize observes existing fork
// bytes; confirmed absence is zero. Inline storage does not query fork length.
// Native authorization belongs to these actual operations; foreign providers
// must retain their producer's Darwin metadata instead of using host flag bits.
type CompressionInstallationBackend interface {
	CompressionCommitBackend
	OpenCompressionFork() (CompressionForkWriter, error)
	CompressionForkSize() (int64, error)
}

// CompressionInstallationResult retains both stages, including ignored errors
// and partial mutations. Fork.Declined means the independent fork was preserved;
// in this case Commit contains only synchronization/timestamp restoration and
// no attribute, truncation or flag writes. Activated is in Commit.
type CompressionInstallationResult struct {
	Fork   CompressionForkResult
	Commit CompressionCommitResult
}

// InstallCompression composes the native fork and final-commit protocols for
// privately staged storage from decmpfs.Encode. Encoding, input authorization,
// volume policy and source stability are caller responsibilities. The source
// stat must precede encoding reads, so access time can be restored. The stage
// and data handle remain caller-owned. This is not an open-path queue API.
//
// No mutation is rolled back. Failed/short fork writes stop before the data fork
// is truncated. Ignored sync/close failures remain visible. Cancellation stops
// before truncation; once truncation succeeds, CommitCompression completes the
// activation/restoration transition before returning cancellation.
func InstallCompression(ctx context.Context, storage decmpfs.EncodedFile, stage io.ReaderAt, source StatCopySource, backend CompressionInstallationBackend) (result CompressionInstallationResult, err error) {
	if backend == nil || storage.ForkSize < 0 || source.Mode > 65535 {
		return result, fs.ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = internal.ValidateLayout(storage.Attribute, uint64(len(storage.Attribute)), 0, uint64(storage.ForkSize)); err != nil {
		return result, err
	}
	fork, err := backend.OpenCompressionFork()
	if err != nil {
		return result, err
	}
	if fork == nil {
		return result, fs.ErrInvalid
	}
	var existing int64
	if storage.ForkSize > 0 {
		if err = ctx.Err(); err == nil {
			existing, err = backend.CompressionForkSize()
		}
		if err != nil {
			finishCompressionFork(fork, &result.Fork)
			return result, errors.Join(err, ctx.Err())
		}
	}
	result.Fork, err = InstallCompressionFork(ctx, storage, stage, existing, fork)
	if err != nil {
		return result, err
	}
	if result.Fork.Declined {
		restoreCompressionDecline(source, backend, &result.Commit)
		return result, ctx.Err()
	}
	result.Commit, err = CommitCompression(ctx, storage, source, backend)
	return result, err
}

func finishCompressionFork(fork CompressionForkWriter, result *CompressionForkResult) {
	for _, op := range []struct {
		name string
		run  func() error
	}{{"fork-sync", fork.Sync}, {"fork-close", fork.Close}} {
		if e := op.run(); e != nil {
			result.Failures = append(result.Failures, StatCopyFailure{op.name, e})
		}
	}
}
