package hostdata

import (
	"context"
	"io"
	"io/fs"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

// InstallHeldCompression binds InstallCompression to one already-open regular
// Darwin file. It opens the resource fork relative to the held descriptor,
// retains its identity and closes the fork before the final metadata transition.
// File and privately staged input remain caller-owned. Source stat and storage
// must describe this stable file before encoding changed its access time.
//
// This is the native Darwin binding. Explicit foreign metadata on every host
// uses InstallCompression; this API never interprets native Linux/Windows bits
// as Darwin compression state. Eligibility and volume selection precede it.
func InstallHeldCompression(ctx context.Context, file *os.File, storage decmpfs.EncodedFile, stage io.ReaderAt, source StatCopySource) (CompressionInstallationResult, error) {
	return installHeldCompressionUsing(ctx, file, storage, stage, source, newHeldCompressionInstallation)
}

func installHeldCompressionUsing(ctx context.Context, file *os.File, storage decmpfs.EncodedFile, stage io.ReaderAt, source StatCopySource, bind func(*os.File) (CompressionInstallationBackend, error)) (CompressionInstallationResult, error) {
	if err := ctx.Err(); err != nil {
		return CompressionInstallationResult{}, err
	}
	if file == nil {
		return CompressionInstallationResult{}, fs.ErrInvalid
	}
	backend, err := bind(file)
	if err != nil {
		return CompressionInstallationResult{}, err
	}
	return InstallCompression(ctx, storage, stage, source, backend)
}
