package hostdata

import (
	"context"
	"io/fs"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

// CommitHeldCompression binds CommitCompression to the caller's already-open
// regular Darwin file. The caller has installed any new fork storage and keeps
// the logical input stable until this transition. Source contains the original
// mode and times captured before encoding changed access time. The file remains
// caller-owned. Every operation uses the held descriptor, including futimes;
// renaming the path does not redirect the transition.
//
// This is the native Darwin view. On other hosts, CommitCompression binds the
// same transition to an explicit foreign metadata backend; native Linux flags
// and Windows attributes cannot stand in for Darwin compression state.
func CommitHeldCompression(ctx context.Context, file *os.File, storage decmpfs.EncodedFile, source StatCopySource) (CompressionCommitResult, error) {
	return commitHeldCompressionUsing(ctx, file, storage, source, newHeldCompressionCommit)
}

func commitHeldCompressionUsing(ctx context.Context, file *os.File, storage decmpfs.EncodedFile, source StatCopySource, bind func(*os.File) (CompressionCommitBackend, error)) (CompressionCommitResult, error) {
	if err := ctx.Err(); err != nil {
		return CompressionCommitResult{}, err
	}
	if file == nil {
		return CompressionCommitResult{}, fs.ErrInvalid
	}
	backend, err := bind(file)
	if err != nil {
		return CompressionCommitResult{}, err
	}
	return CommitCompression(ctx, storage, source, backend)
}
