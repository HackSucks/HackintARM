package recompression

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"

	internal "github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type recompressionSource struct{ appledouble.Value }

func (s recompressionSource) Size() uint64 { return uint64(s.Value.Size()) }

// validateRecompressionStorage binds active compressed bytes to the original
// materialization baseline, even when the caller intentionally edited the
// materialized payload. A malformed or mismatched original cannot be healed by
// silently discarding it. Inactive attributes deliberately never enter here.
func validateRecompressionStorage(ctx context.Context, values map[string]appledouble.Value, baseline metatransport.BlobRef) error {
	attr := values[hostdata.DecmpfsName]
	fork, err := internal.UsesResourceFork(attr)
	if err != nil {
		return err
	}
	headerBytes := make([]byte, internal.HeaderSize)
	n, err := attr.ReadAt(headerBytes, 0)
	if n != len(headerBytes) || err != nil && !errors.Is(err, io.EOF) {
		return errors.Join(io.ErrUnexpectedEOF, err)
	}
	header, err := internal.ParseHeader(headerBytes)
	if err != nil || header == nil || header.UncompressedDataSize != uint64(baseline.Size) {
		return errors.Join(metatransport.ErrCorrupt, err)
	}
	source := attr
	forkSize := int64(0)
	if value := values[hostdata.ResourceForkName]; value != nil {
		forkSize = value.Size()
	}
	if err = internal.ValidateLayout(headerBytes, uint64(attr.Size()), 0, uint64(forkSize)); err != nil {
		return err
	}
	if fork {
		source = values[hostdata.ResourceForkName]
		if source == nil {
			return metatransport.ErrCorrupt
		}
	}
	method, err := internal.MethodFor(header.CompressionMethod)
	if err != nil {
		return err
	}
	decoder, err := internal.NewHandle(recompressionSource{source}, header.UncompressedDataSize, method)
	if err != nil {
		return err
	}
	defer decoder.Close()
	hash := sha256.New()
	buffer := make([]byte, 65536)
	for remaining := baseline.Size; remaining > 0; {
		if err = ctx.Err(); err != nil {
			return err
		}
		chunk := buffer[:min(int64(len(buffer)), remaining)]
		n, err = decoder.ReadSegmentData(0, chunk)
		if n != len(chunk) || err != nil && !errors.Is(err, io.EOF) {
			return errors.Join(io.ErrUnexpectedEOF, err)
		}
		_, _ = hash.Write(chunk)
		remaining -= int64(n)
	}
	if hex.EncodeToString(hash.Sum(nil)) != baseline.SHA256 {
		return metatransport.ErrCorrupt
	}
	return ctx.Err()
}

// Read only the declared kauth_filesec extent. Trailing opaque bytes are
// retained in the carrier but cannot add authorization entries. The format's
// native ACL entry bound prevents an untrusted length from allocating a blob.
func readRecompressionSecurity(value appledouble.Value) (*appledouble.FileSecurity, error) {
	if value.Size() < 44 {
		return nil, appledouble.ErrFileSecurity
	}
	header := make([]byte, 44)
	n, err := value.ReadAt(header, 0)
	if n != len(header) || err != nil && !errors.Is(err, io.EOF) {
		return nil, errors.Join(io.ErrUnexpectedEOF, err)
	}
	count := binary.BigEndian.Uint32(header[36:40])
	if count == ^uint32(0) {
		return appledouble.ParseFileSecurity(header)
	}
	if count > 128 {
		return nil, appledouble.ErrFileSecurity
	}
	size := int64(44) + int64(count)*24
	if value.Size() < size {
		return nil, appledouble.ErrFileSecurity
	}
	body := make([]byte, size)
	n, err = value.ReadAt(body, 0)
	if n != len(body) || err != nil && !errors.Is(err, io.EOF) {
		return nil, errors.Join(io.ErrUnexpectedEOF, err)
	}
	return appledouble.ParseFileSecurity(body)
}
