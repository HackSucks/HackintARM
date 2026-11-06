package metatransport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// PayloadReference fingerprints a held regular payload with bounded scratch.
// The caller owns the descriptor and excludes concurrent content changes.
func PayloadReference(ctx context.Context, file interface {
	io.ReaderAt
	Stat() (os.FileInfo, error)
}) (BlobRef, error) {
	info, err := file.Stat()
	if err != nil {
		return BlobRef{}, err
	}
	hash := sha256.New()
	if err = copyExact(ctx, hash, file, info.Size()); err != nil {
		return BlobRef{}, err
	}
	return BlobRef{SHA256: hex.EncodeToString(hash.Sum(nil)), Size: info.Size()}, nil
}

// VerifyHeldPayload checks a held payload's exact size and SHA-256 baseline.
// It does not acquire a pathname or check its association with a carrier record.
func VerifyHeldPayload(ctx context.Context, file interface {
	io.ReaderAt
	Stat() (os.FileInfo, error)
}, ref BlobRef) error {
	return verify(ctx, file, ref)
}

// CopyPayload writes exactly size bytes from offset zero using bounded scratch
// and cancellation checkpoints. The destination starts at its current offset.
// The caller owns both streams and any partial destination after failure.
func CopyPayload(ctx context.Context, dst io.Writer, src io.ReaderAt, size int64) error {
	return copyExact(ctx, dst, src, size)
}
