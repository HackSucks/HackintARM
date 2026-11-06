package recompression

import (
	"context"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

// Held payload operations are deliberately separate from manifest publication:
// failed writes may leave partial ordinary data, but never a successful manifest.
type recompressionPayloadFile interface {
	io.ReaderAt
	io.Writer
	io.Seeker
	Stat() (os.FileInfo, error)
	Truncate(int64) error
	Sync() error
	Close() error
}

func publishRecompressionPayload(ctx context.Context, s carrier, data recompressionPayloadFile, aliases []recompressionAlias, record metatransport.Record, before metatransport.BlobRef, empty bool) error {
	if e := s.CheckPayload(ctx, record.Materialized, data); e != nil {
		return e
	}
	if e := metatransport.VerifyHeldPayload(ctx, data, before); e != nil {
		return e
	}
	for _, alias := range aliases {
		if e := s.CheckPayload(ctx, alias.record.Materialized, alias.file); e != nil {
			return e
		}
		if e := metatransport.VerifyHeldPayload(ctx, alias.file, alias.baseline); e != nil {
			return e
		}
	}
	if empty {
		if e := data.Truncate(0); e != nil {
			return e
		}
		for _, alias := range aliases {
			if e := alias.file.Truncate(0); e != nil {
				return e
			}
		}
		if e := data.Sync(); e != nil {
			return e
		}
		for _, alias := range aliases {
			if e := alias.file.Sync(); e != nil {
				return e
			}
		}
	}
	if !empty {
		for _, alias := range aliases {
			if !alias.copyPayload {
				continue
			}
			if e := alias.file.Truncate(0); e != nil {
				return e
			}
			if _, e := alias.file.Seek(0, 0); e != nil {
				return e
			}
			if e := metatransport.CopyPayload(ctx, alias.file, data, before.Size); e != nil {
				return e
			}
			if e := alias.file.Sync(); e != nil {
				return e
			}
		}
	}
	return nil
}
