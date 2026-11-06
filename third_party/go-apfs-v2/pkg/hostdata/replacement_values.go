package hostdata

import (
	"context"
	"fmt"
	"io/fs"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// ReplacementAttributeValues selects the attributes retained when replacing a
// logical Darwin file with rewritten, uncompressed data. sourceFlags must be
// captured Darwin BSD flags, never Linux flags or Windows file attributes.
// Native replacement enumerates the ordinary visible namespace: active
// compression hides both decmpfs and ResourceFork, including an independent
// fork on an inline-compressed file. Both are omitted. With UF_COMPRESSED clear,
// these attributes remain ordinary metadata, even if their bytes are opaque.
// The kernel visibility predicate compares these reserved name prefixes.
//
// The returned map is independent, but its values remain borrowed from the
// caller. Only the compression header is read; neither ordinary attributes nor
// large resource forks are materialized. Unknown or malformed active headers
// fail without publishing a result or modifying the input map. The caller owns
// stat/security restoration, clearing the old compression flag, association
// validation and publication through its carrier's normal transaction boundary.
func ReplacementAttributeValues(ctx context.Context, sourceFlags uint32, attributes map[string]appledouble.Value) (map[string]appledouble.Value, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	compressed := sourceFlags&UFCompressed != 0
	if compressed {
		_, err := decmpfs.UsesResourceFork(attributes[DecmpfsName])
		if err != nil {
			return nil, fmt.Errorf("replacement compression: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make(map[string]appledouble.Value, len(attributes))
	for name, value := range attributes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if value == nil || value.Size() < 0 {
			return nil, fs.ErrInvalid
		}
		if replacementVisibleAttribute(compressed, name) {
			result[name] = value
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func replacementVisibleAttribute(compressed bool, name string) bool {
	return !compressed || !strings.HasPrefix(name, DecmpfsName) && !strings.HasPrefix(name, ResourceForkName)
}
