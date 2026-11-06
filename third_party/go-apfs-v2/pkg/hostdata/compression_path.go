package hostdata

import (
	"context"
	"errors"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/bsdflags"
)

// QueryCompressionNoFollow observes native Darwin compression without opening
// file contents. This is needed when an ACL allows metadata reads but denies
// data access, or when opening a writer would decompress the source. expected
// must identify the regular file already observed by the caller. Identity is
// checked before and after attribute reads; the final symlink is never followed.
//
// Each native pathname operation resolves independently. These checks detect
// observed replacement, not an adversarial replace-and-restore race. Callers
// must exclude concurrent namespace and content changes; this is not a rooted
// handle acquisition. Prefer QueryCompression on an already-held descriptor.
// Other hosts supply captured Darwin metadata to decmpfs.Query instead.
func QueryCompressionNoFollow(ctx context.Context, path string, expected os.FileInfo, attributeBytes int) (decmpfs.Info, error) {
	return queryCompressionPathUsing(ctx, path, expected, attributeBytes, os.Lstat, bsdflags.Flags, nativeCompressionPathXattr)
}

func queryCompressionPathUsing(ctx context.Context, path string, expected os.FileInfo, limit int, stat func(string) (os.FileInfo, error), flags func(os.FileInfo) (uint32, bool), get func(string, string, []byte) (int, error)) (decmpfs.Info, error) {
	if ctx == nil || expected == nil || !expected.Mode().IsRegular() || limit < 0 {
		return decmpfs.Info{}, os.ErrInvalid
	}
	metadata, err := captureCompressionMetadata(ctx, limit, func() (uint32, uint64, error) {
		current, err := stat(path)
		if err != nil {
			return 0, 0, err
		}
		if current.Size() < 0 {
			return 0, 0, os.ErrInvalid
		}
		if !current.Mode().IsRegular() || !os.SameFile(expected, current) {
			return 0, 0, ErrMetadataIdentity
		}
		value, ok := flags(current)
		if !ok {
			return 0, 0, errors.ErrUnsupported
		}
		return value, uint64(current.Size()), nil
	}, func(name string, b []byte) (int, error) { return get(path, name, b) })
	if err != nil {
		return decmpfs.Info{}, err
	}
	return decmpfs.Query(ctx, metadata)
}
